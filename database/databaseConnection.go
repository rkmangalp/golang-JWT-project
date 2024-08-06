package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DBinstance initializes and returns a MongoDB client instance.
func DBinstance() *mongo.Client {
	// Load environment variables from the .env file.
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get the MongoDB connection string from the environment variables.
	MongoDb := os.Getenv("MONGODB_URL")

	// Create a new MongoDB client with the connection string.
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDb))
	if err != nil {
		log.Fatal(err)
	}

	// Create a context with a timeout of 10 seconds for the connection.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB using the client and context.
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Print a success message if the connection is established.
	fmt.Println("connected to MongoDB!")

	// Return the MongoDB client instance.
	return client
}

// Client is a global variable holding the MongoDB client instance.
var Client *mongo.Client = DBinstance()

// OpenCollection opens a specific collection from the MongoDB database.
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	// Get a reference to the collection with the specified name in the "cluster0" database.
	var Collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)

	// Return the collection reference.
	return Collection
}
