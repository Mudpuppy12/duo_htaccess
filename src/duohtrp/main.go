package main

import (
	"log"
	"net"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
	"github.com/foomo/htpasswd"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
)

const userAgent = "duohtrp"

var (
	IKEY    string
	SKEY    string
	HOST    string
	FILE    string
	BACKEND string
)

func init() {

	viper.SetConfigName("config") // no need to include file extension
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()

	if err != nil { // Handle errors reading the config file
		log.Fatal(err)
	}

	IKEY = viper.GetString("duohtrp.ikey")
	SKEY = viper.GetString("duohtrp.skey")
	HOST = viper.GetString("duohtrp.host")
	FILE = viper.GetString("duohtrp.htpasswd_file")
	BACKEND = viper.GetString("duohtrp.backend")

}

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func DuoPreAuth(username string) bool {

	duo := authapi.NewAuthApi(*duoapi.NewDuoApi(IKEY, SKEY, HOST, userAgent))

	result, err := duo.Preauth(authapi.PreauthUsername(username))

	if err != nil {
		return false
	}

	if result.Stat != "OK" {
		return false
	}

	if result.Response.Result != "auth" {
		return false
	}
	return true
}

func DuoAuth(username string) bool {
	duo := authapi.NewAuthApi(*duoapi.NewDuoApi(IKEY, SKEY, HOST, userAgent))
	auth, err := duo.Auth("auto",
		authapi.AuthUsername(username),
		authapi.AuthIpAddr(GetOutboundIP().String()),
		authapi.AuthDevice("auto"),
		authapi.AuthType("request"),
		authapi.AuthDisplayUsername(username),
	)

	if err != nil {
		return false
	}

	if auth.Stat != "OK" {
		return false
	}
	if auth.Response.Result != "allow" {
		return false
	}
	if auth.Response.Status != "allow" {
		return false
	}
	if auth.Response.Status_Msg != "Success. Logging you in..." {
		return false
	}
	return true
}

func CheckDuo() bool {

	duo := authapi.NewAuthApi(*duoapi.NewDuoApi(IKEY, SKEY, HOST, userAgent))

	result, err := duo.Check()

	if err != nil {
		return false
	}
	if result.Stat != "OK" {
		return false

	}
	return true
}

func main() {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	if CheckDuo() == false {
		e.Logger.Fatal("Can't talk to DUO Api Correctly.")
	}

	// Setup proxy
	url1, err := url.Parse(BACKEND)
	if err != nil {
		e.Logger.Fatal(err)
	}

	e.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {

		passwords, err := htpasswd.ParseHtpasswdFile(FILE)

		if err != nil {
			return false, nil
		}

		err = bcrypt.CompareHashAndPassword([]byte(passwords[username]),
			[]byte(password))

		if err != nil {
			return false, nil
		}

		if DuoPreAuth(username) {
			if DuoAuth(username) {
				return true, nil
			}
		}
		return false, nil
	}))

	e.Use(middleware.Proxy(&middleware.RoundRobinBalancer{
		Targets: []*middleware.ProxyTarget{
			&middleware.ProxyTarget{
				URL: url1,
			},
		},
	}))

	e.Logger.Fatal(e.Start(":9999"))
}
