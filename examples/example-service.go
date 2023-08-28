package main

import (
	"fmt"
	"github.com/New-Horizons-Team/leakspok"
	"github.com/gofiber/fiber/v2"
	"log"
	"strings"
)

type RequestBody struct {
	Data string `json:"data"`
}

func main() {
	// Fiber instance
	app := fiber.New()

	// Routes
	app.Get("/", hello)
	// curl  -X POST http://127.0.0.1:3000/check_pii -H "Content-Type: application/json"
	//-d '{"data": "PIIXXXXXX"}'
	app.Post("/check_pii", checkPII)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

// Handler
func hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World 👋!")
}

// checkPII2 checks for PII information passed on body
func checkPII(c *fiber.Ctx) error {

	var body RequestBody

	// Parse the JSON body into the RequestBody struct
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Cannot parse JSON",
		})
	}

	// Print the parsed data to the console
	fmt.Println("Received:", body.Data)

	t := leakspok.NewDefaultStringTester()
	lines := strings.Split(body.Data, "\n")
	result, err := t.Find(lines)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "error on evaluating body",
		})
	}

	return c.JSON(result)
}
