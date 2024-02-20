package routes

import (
	"echo-mongo/controllers"

	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
	e.POST("/user/signup", controllers.SignUp)
	e.GET("/user/signin", controllers.SignIn)
}
