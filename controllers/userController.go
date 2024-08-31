package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rkmangalp/golang-JWT-project/database"
	"github.com/rkmangalp/golang-JWT-project/helpers"
	"github.com/rkmangalp/golang-JWT-project/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(hashedPassword)
}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")
		check = false
	}
	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		// Ensure the context is canceled to free up resources.
		defer cancel()

		// Define a variable to hold the user data.
		var user models.User

		// Bind the JSON body of the request to the user variable.
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate the user data.
		validateErr := validate.Struct(user)
		if validateErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
			return
		}

		// Check if an account with the same email already exists.
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking the email"})
			return
		}
		// If an account with the same email exists, return an error.
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this email already exists"})
			return
		}
		password := HashPassword(*user.Password)
		user.Password = &password
		// Check if an account with the same phone number already exists.
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking the phone"})
			return
		}
		// If an account with the same phone number exists, return an error.
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this phone number already exists"})
			return
		}

		// Set the Created_at and Updated_at fields to the current time.
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		// Generate a new unique ID for the user.
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		// Generate authentication tokens for the user.
		token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		// Insert the new user document into the userCollection.
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := "User item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		// Return the result of the insertion.
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User      // Variable to hold user input
		var foundUser models.User // Variable to hold the found user
		defer cancel()            // Ensure the context is canceled at the end

		// Bind incoming JSON request to user struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Return error if binding fails
			return
		}

		// Find the user in the database by email
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode((&foundUser))
		defer cancel() // Again, cancel context if needed
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"}) // Return error if user not found
			return
		}

		// Verify the password provided against the stored password
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel() // Cancel context if needed
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg}) // Return error if password is invalid
			return
		}

		// Check if the user was found
		if foundUser.Email == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"}) // Return error if no email
		}

		// Generate JWT and refresh token for the found user
		token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, &foundUser.User_type, *&foundUser.User_id)

		// Update the user's tokens in the database
		helpers.UpdateAllTokens(token, refreshToken, foundUser.User_id)

		// Retrieve updated user information from the database
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		// Return error if fetching updated user info fails
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Return the found user information as JSON
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if the current user has ADMIN role. Return an error if not.
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Create a context with a 100-second timeout for the database operation.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel() // Ensure context is canceled after the operation

		// Get pagination parameters from the query string.
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10 // Default number of records per page
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1 // Default page number
		}

		// Calculate the starting index for pagination.
		startIndex := (page - 1) * recordPerPage

		// MongoDB aggregation pipeline stages.

		// Match stage: To include all documents in this example.
		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}

		// Group stage: Groups all documents and calculates the total count.
		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "null"},
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
		}

		// Project stage: Selects fields to return and applies pagination.
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		// Perform the aggregation operation on the userCollection.
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})

		// Handle any errors during the aggregation.
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing items"})
			return
		}

		// Retrieve all documents from the result.
		var allUsers []bson.M
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		// Return the result as JSON.
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Retrieve the user ID from the URL parameter.
		userId := c.Param("user_id")

		// Match the user type and user ID from the context to ensure the user has permission to access this resource.
		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Create a context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		// Ensure the context is canceled to free up resources after the function completes.
		defer cancel()

		// Define a variable to hold the user data.
		var user models.User

		// Find the user document in the collection using the user ID.
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Return the user data as a JSON response.
		c.JSON(http.StatusOK, user)
	}
}
