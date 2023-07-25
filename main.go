package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	sUtils "github.com/projectdiscovery/utils/slice"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Dump struct {
	Subdomains []string `bson:"subdomains"`
}

type UnResolve struct {
	Name       string   `bson:"name"`
	UnResolved []string `bson:"unResolved"`
}

type SubdomainData struct {
	Date       string   `bson:"date"`
	Subdomains []string `bson:"subdomains"`
}

type Insert struct {
	Name       string          `bson:"name"`
	ProgramUrl string          `bson:"program_url"`
	Platform   string          `bson:"platform"`
	Subdomains []SubdomainData `bson:"subdomains"`
}

type Output struct {
	Name        string `json:"name"`
	ProgramUrl  string `json:"program_url"`
	URL         string `json:"URL"`
	Count       int    `json:"count"`
	Change      int    `json:"change"`
	IsNew       bool   `json:"is_new"`
	Platform    string `json:"platform"`
	Bounty      bool   `json:"bounty"`
	LastUpdated string `json:"last_updated"`
}

func main() {
	gologger.Info().Msgf("Connecting to DB...\n")
	client, err := connectToMongoDB()
	if err != nil {
		gologger.Error().Msgf("Unable to connect to MongoDB: %v\n", err)
	}
	defer client.Disconnect(context.Background())

	gologger.Info().Msgf("Fetching data from Chaos...\n")
	output, err := fetchChaosData()
	if err != nil {
		gologger.Error().Msgf("Failed to fetch chaos data: %v\n", err)
	}

	if err := insertToDatabase(output, client); err != nil {
		gologger.Error().Msgf("Failed to insert data to database: %v\n", err)
	}
}

func insertToDatabase(data []Output, client *mongo.Client) error {

	SkipNames := make(map[string]bool)

	// exclude Programs that data is false positive
	f, err := os.Open("exclude.txt")
	if err != nil {
		log.Printf("[WARN] Could not read exclude.txt: %s\n", err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		text := scanner.Text()
		if text != "" {
			SkipNames[text] = true
		}
	}

	for _, v := range data {
		if v.Bounty && !SkipNames[v.Name] && v.Change > 0 {
			gologger.Info().Msgf("Processing %v\n", v.Name)

			// Get content of zip file
			zipData, err := getRequest(v.URL)
			if err != nil {
				return err
			}

			tempFile, err := ioutil.TempFile("", v.Name+".zip")
			if err != nil {
				return fmt.Errorf("failed to create temporary file: %w", err)
			}
			defer os.Remove(tempFile.Name())

			if _, err = io.Copy(tempFile, bytes.NewReader(zipData)); err != nil {
				return fmt.Errorf("failed to save zip file: %w", err)
			}
			tempFile.Close()

			zipFile, err := zip.OpenReader(tempFile.Name())
			if err != nil {
				return fmt.Errorf("failed to open zip file: %w", err)
			}
			defer zipFile.Close()

			gologger.Print().Msgf("Extracting Subdomains from zip")
			newSubdomains, err := extractSubdomains(zipFile)
			if err != nil {
				return err
			}

			gologger.Print().Msgf("Extracting Subdomains from Database")
			oldSubdomains, err := fetchSubdomainsFromDB(client, v.Name)
			if err != nil {
				return err
			}

			gologger.Print().Msgf("Comparing Subdomains")
			diffSubdomains, _ := sUtils.Diff(newSubdomains, oldSubdomains)

			if len(diffSubdomains) > 0 {
				gologger.Print().Msgf("Updating Program's Database")
				dom := bson.M{}
				update3 := bson.M{"$push": bson.M{"subdomains": bson.M{"$each": diffSubdomains}}}

				_, err := client.Database("Programs").Collection(v.Name).UpdateOne(context.TODO(), dom, update3)
				if err != nil {
					return err
				}

				gologger.Print().Msgf("Resolving New Subdomains")
				// Resolve all subdomains and splits
				resolved, unresolved := Resolve(diffSubdomains)

				sub := []SubdomainData{{
					Date:       time.Now().Format("January-2-2006"),
					Subdomains: resolved},
				}

				res := Insert{
					Name:       v.Name,
					ProgramUrl: v.ProgramUrl,
					Platform:   v.Platform,
					Subdomains: sub,
				}

				unres := UnResolve{
					Name:       v.Name,
					UnResolved: unresolved,
				}

				// Define the filter to find the document
				filter := bson.M{"name": v.Name}

				if len(resolved) > 0 {
					gologger.Print().Msgf("Update or Insert Data")
					// Find the document
					var result Insert
					err = client.Database("Processed").Collection("Data").FindOne(context.Background(), filter).Decode(&result)
					if err == nil {
						// Append new subdomains and update the date if the document exists
						if result.Name == v.Name {
							result.Subdomains = append(result.Subdomains, SubdomainData{
								Date:       time.Now().Format("January-2-2006"),
								Subdomains: resolved})

							update := bson.M{
								"$set": bson.M{
									"subdomains": result.Subdomains,
								},
							}

							_, err = client.Database("Processed").Collection("Data").UpdateOne(context.Background(), filter, update)
							if err != nil {
								log.Fatal(err)
							}
						}
					} else {
						if len(resolved) > 0 {
							// Insert into DB
							_, err = client.Database("Processed").Collection("Data").InsertOne(context.Background(), res)
							if err != nil {
								panic(err)
							}
						}
					}
				}

				if len(unresolved) > 0 {
					gologger.Print().Msgf("Update or Insert new UnResolved subdomains")
					var result2 UnResolve
					err = client.Database("Processed").Collection("UnResolved").FindOne(context.Background(), filter).Decode(&result2)
					if err == nil {
						if result2.Name == v.Name {
							for _, a := range unresolved {
								result2.UnResolved = append(result2.UnResolved, a)
							}
							update2 := bson.M{
								"$set": bson.M{"unResolved": result2.UnResolved},
							}
							_, err = client.Database("Processed").Collection("UnResolved").UpdateOne(context.Background(), filter, update2)
							if err != nil {
								log.Fatal(err)
							}
						}
					} else {
						// Insert into DB
						_, err = client.Database("Processed").Collection("UnResolved").InsertOne(context.Background(), unres)
						if err != nil {
							panic(err)
						}
					}
				}
				if len(resolved) > 0 {
					gologger.Print().Msgf("Sending data to Discord")
					message := "### " + time.Now().Format("January-2-2006") + "\n```yaml\n" +
						"Name: \n - " + res.Name + "\n" +
						"Program URL: \n - " + res.ProgramUrl + "\n" +
						"Platform: \n - " + res.Platform + "\n" +
						"Subdomains: \n" + formatSubdomains(resolved) + "```"

					// Replace "YOUR_DISCORD_WEBHOOK_URL" with your actual Discord webhook URL
					webhookURL := "<DISCORD WEBHOOK>"

					// Create the payload
					payload := map[string]string{
						"content": message,
					}

					// Convert payload to JSON
					jsonPayload, err := json.Marshal(payload)
					if err != nil {
						log.Fatal(err)
					}

					// Send the POST request to the Discord webhook URL
					resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
					if err != nil {
						log.Fatal(err)
					}
					defer resp.Body.Close()
				}
			}
		}
	}
	return nil
}

func getRequest(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func extractSubdomains(zipFile *zip.ReadCloser) ([]string, error) {
	var subdomains []string

	for _, file := range zipFile.File {
		zippedFile, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file within zip: %w", err)
		}
		defer zippedFile.Close()

		data, err := io.ReadAll(zippedFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file within zip: %w", err)
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			if trimmedLine != "" {
				subdomains = append(subdomains, trimmedLine)
			}
		}
	}

	return subdomains, nil
}

func fetchSubdomainsFromDB(client *mongo.Client, collectionName string) ([]string, error) {
	filter := map[string]interface{}{}

	cursor, err := client.Database("Programs").Collection(collectionName).Find(context.Background(), filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var subdomains []string
	for cursor.Next(context.Background()) {
		var result Dump
		err = cursor.Decode(&result)
		if err != nil {
			return nil, err
		}
		subdomains = append(subdomains, result.Subdomains...)
	}
	return subdomains, nil
}

func connectToMongoDB() (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI("<YOUR MONGO-DB URL>")
	return mongo.Connect(context.Background(), clientOptions)
}

func fetchChaosData() ([]Output, error) {
	resp, err := http.Get("https://chaos-data.projectdiscovery.io/index.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var output []Output
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, err
	}
	return output, nil
}

func Resolve(domains []string) (Resolved []string, Unresolved []string) {
	resolved := make([]string, 0)
	unresolved := make([]string, 0)
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	for _, domain := range domains {
		// DNS A question and returns corresponding IPs
		_, unres := dnsClient.Lookup(domain)
		if unres != nil {
			unresolved = append(unresolved, domain)
		} else {
			resolved = append(resolved, domain)
		}
	}
	return resolved, unresolved
}

// Helper function to format the subdomains as a string
func formatSubdomains(subdomains []string) string {
	var formatted string
	for _, subs := range subdomains {
		formatted += " - " + subs + "\n"
	}
	return formatted
}
