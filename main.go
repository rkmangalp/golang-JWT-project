package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rkmangalp/golang-JWT-project/routes"
)

func main() {
	// Retrieve the port number from the environment variable "PORT".
	port := os.Getenv("PORT")

	// If the "PORT" environment variable is not set, default to port 8000.
	if port == "" {
		port = "9000"
	}

	// Create a new Gin router instance.
	router := gin.New()

	// Use the default logger middleware provided by Gin to log requests.
	router.Use(gin.Logger())

	// Register authentication routes from the routes package.
	routes.AuthRoutes(router)

	// Register user-related routes from the routes package.
	routes.UserRoutes(router)

	// Define a GET endpoint "/api-1".
	router.GET("/api-1", func(c *gin.Context) {
		// Respond with a JSON object indicating success.
		c.JSON(200, gin.H{"success": "Access granted for api-1"})
	})

	// Define a GET endpoint "/api-2".
	router.GET("/api-2", func(c *gin.Context) {
		// Respond with a JSON object indicating success.
		c.JSON(200, gin.H{"success": "Access granted for api-2"})
	})

	// Run the router on the specified port.
	router.Run(":" + port)
}
