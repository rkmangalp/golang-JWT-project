package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/rkmangalp/golang-JWT-project/controllers"
)

// AuthRoutes defines the routes for user authentication.
func AuthRoutes(incomingRoutes *gin.Engine) {
    // Route for user signup:
    // When a POST request is made to "user/signup", the Signup controller handles it.
    incomingRoutes.POST("user/signup", controllers.Signup())
    
    // Route for user login:
    // When a POST request is made to "user/login", the Login controller handles it.
    incomingRoutes.POST("user/login", controllers.Login())
}
