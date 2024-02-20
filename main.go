package main

import (
	"echo-mongo/configs"
	"echo-mongo/routes"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	// run database
	configs.ConnectDB()

	routes.UserRoute(e)

	e.Logger.Fatal(e.Start(":3000"))
}
