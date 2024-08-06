package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/rkmangalp/golang-JWT-project/controllers"
	"github.com/rkmangalp/golang-JWT-project/middleware"
)

// UserRoutes defines the routes related to user operations.
func UserRoutes(incomingRoutes *gin.Engine) {

	// Apply the authentication middleware to all routes defined in this function.
	incomingRoutes.Use(middleware.Authenticate())

	// Define a route for getting a list of users.
	// The GET request to "/users" will be handled by the GetUsers controller function.
	incomingRoutes.GET("/users", controllers.GetUsers())

	// Define a route for getting a specific user by user ID.
	// The GET request to "/user/:user_id" will be handled by the GetUser controller function.
	// ":user_id" is a path parameter that will be passed to the controller function.
	incomingRoutes.GET("/user/:user_id", controllers.GetUser())
}
