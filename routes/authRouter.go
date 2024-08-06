package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/rkmangalp/golang-JWT-project/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("user/signup", controllers.Signup())
	incomingRoutes.POST("user/login", controllers.Login())
}
