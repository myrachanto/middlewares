package middlewares

import (
	"fmt"
	"os"
	// "fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

//IsAdmin middleware evalutes if the user is admin - super admin
func IsAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file in routes")
	}
	key := os.Getenv("EncryptionKey")
	return func(c echo.Context) error {
		headertoken := c.Request().Header.Get("Authorization")
		token := strings.Split(headertoken, " ")[1]
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token)(interface{}, error){
			return []byte(key), nil
		})
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "unable to parse token")
		}
		// fmt.Println("fc", fc)
		// level := claims["role"].(string)
		admin := claims["admin"].(string)
		supervisor := claims["supervisor"].(string)
		employee := claims["employee"].(string)
		fmt.Println("role", admin)
		if admin != "admin" {
			return echo.NewHTTPError(http.StatusForbidden, "unable to parse token")
		}
		if supervisor != "supervisor"{
			return echo.NewHTTPError(http.StatusForbidden, "unable to parse token")
		}
		if employee != "employee" {
			return echo.NewHTTPError(http.StatusForbidden, "unable to parse token")
		}
		return next(c)
	}
}