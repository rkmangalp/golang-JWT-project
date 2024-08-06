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

func HashPassword(password string) string{
	bcrypt.GenerateFromPassword([]byte(password, 14))
	if err != nil{
		log.Panic(err)
	}
	return string(bytes)
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
		var user models.User
		var foundUser models.User
		defer cancel()

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode((&foundUser))
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == ""{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, &foundUser.User_type, *&foundUser.User_id)
		helpers.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err := userCollection.FindOne(ctx, bson.M{"user_id":foundUser.User_id}).Decode(&foundUser)

		if err != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc{
	return func(c *gin.Context){
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return 
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1{
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1{
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}}, 
			{"data", bson.D{{"$push", "$$ROOT"}}},
		}}}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id",0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			}}
		}
	result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
		matchStage, groupStage, projectStage
	})
	defer cancel()
	if err != nil{
		c.JSON{http.StatusInternalServerError, gin.H{"error":"error occured while listing items"}}
	}
	var allUsers []bson.M
	if err = result.All(ctx, &allUsers); err != nil{
		log.Fatal(err)
	}
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
