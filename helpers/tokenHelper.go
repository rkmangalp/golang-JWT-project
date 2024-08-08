package helpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"                  // Importing the JWT package for creating and validating tokens.
	"github.com/rkmangalp/golang-JWT-project/database" // Importing the custom database package for MongoDB operations.
	"go.mongodb.org/mongo-driver/bson"                 // BSON package for MongoDB to encode/decode BSON data.
	"go.mongodb.org/mongo-driver/bson/primitive"       // BSON primitives, like ObjectID, used in MongoDB.
	"go.mongodb.org/mongo-driver/mongo"                // MongoDB driver package for Go.
	"go.mongodb.org/mongo-driver/mongo/options"        // Options package for MongoDB operations like UpdateOptions.
)

type SignedDetails struct {
	Email              string
	First_name         string
	Last_name          string
	Uid                string
	User_type          string
	jwt.StandardClaims // Embedding standard JWT claims like ExpiresAt.
}

// Initializes `userCollection` to access the "user" MongoDB collection.
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

// Retrieves the `SECRET_KEY` from environment variables for JWT signing.
var SECRET_KEY string = os.Getenv("SECRET_KEY")

// GenerateAllTokens creates an access token and a refresh token for the user with given details.
// Returns the signed access token, signed refresh token, and any error encountered during the process.
func GenerateAllTokens(email, first_name, last_name, userType, uid string) (signedToken, signedRefreshToken string, err error) {
	// Define the claims for the access token.
	claims := &SignedDetails{
		Email:      email,      // User's email address
		First_name: first_name, // User's first name
		Last_name:  last_name,  // User's last name
		Uid:        uid,        // User's unique identifier
		User_type:  userType,   // Type of user (e.g., admin, regular user)
		StandardClaims: jwt.StandardClaims{
			// Access token expiration time set to 24 hours from the current time
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	// Define the claims for the refresh token with a longer expiration time.
	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			// Refresh token expiration time set to 7 days (168 hours) from the current time
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	// Generate the access token with the defined claims and sign it using the SECRET_KEY.
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err) // Log any error encountered during token signing
		return         // Return empty strings and error if token signing fails
	}

	// Generate the refresh token with the defined claims and sign it using the SECRET_KEY.
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err) // Log any error encountered during token signing
		return         // Return empty strings and error if token signing fails
	}

	// Return the signed access token and refresh token, along with a nil error
	return token, refreshToken, nil
}

// ValidateToken validates a JWT token and extracts its claims.
// It returns the token claims and an error message if validation fails.
func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	// Parse the token with claims and validate it using the SECRET_KEY.
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{}, // Claims structure to parse the token into
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil // Function to provide the key for validation
		},
	)

	// If there's an error during parsing, return the error message.
	if err != nil {
		msg = err.Error()
		return
	}

	// Extract and type assert the claims from the parsed token.
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid") // Invalid claims type
		msg = err.Error()                         // Set error message
		return
	}

	// Check if the token has expired.
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired") // Token is expired
		msg = err.Error()                     // Set error message
		return
	}

	// Return the valid claims and an empty message if validation is successful.
	return claims, msg
}

// UpdateAllTokens updates the JWT access token, refresh token, and the updated timestamp for a user in the MongoDB collection.
func UpdateAllTokens(signedToken string, signedRefreshToken string, userID string) {
	// Create a context with a 100-second timeout for the database operation.
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel() // Ensure context is canceled after the operation

	// Initialize an update object to hold fields to be updated.
	var updateObj primitive.D

	// Add the new access token to the update object.
	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	// Add the new refresh token to the update object.
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})

	// Add the current timestamp as the updated_at field.
	updatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{Key: "updated_at", Value: updatedAt})

	// Define upsert option to create a new document if it does not exist.
	upsert := true
	filter := bson.M{"user_id": userID} // Filter to find the user by userID
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	// Perform the update operation on the MongoDB collection.
	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj}, // Update operation to set new values
		},
		&opt, // Update options with upsert enabled
	)

	// Handle any errors encountered during the update operation.
	if err != nil {
		// Error handling logic should be added here
	}
}
