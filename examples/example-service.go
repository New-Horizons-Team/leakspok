package main

import (
	"fmt"
	"github.com/New-Horizons-Team/leakspok"
	"github.com/gofiber/fiber/v2"
	"log"
	"strconv"
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
	app.Post("/check_pii2", checkPII2)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

// Handler
func hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World 👋!")
}

// checkPII checks for PII information passed on body
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

	t := leakspok.NewDefaultTester()
	//t.SetDetection(true)
	//t.SetFinder(true)
	//t.Setup()

	//detect
	//ts := time.Now()
	lines := strings.Split(body.Data, "\n")
	matched := false
	for _, rule := range t.Rules {
		for _, x := range lines {
			matched = rule.Filter(x)
			if matched {
				break
			}
		}

		//dur := time.Since(ts).Nanoseconds()
		fmt.Println("match: " + rule.Name + " " + strconv.FormatBool(matched))
		//f.DetectionLatencies[rule.Name] = float64(dur) / float64(time.Millisecond)
	}

	// Send a response to the client
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Data received successfully",
		"data":    body.Data,
	})
}

// checkPII2 checks for PII information passed on body
func checkPII2(c *fiber.Ctx) error {

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
