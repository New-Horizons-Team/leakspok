package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/New-Horizons-Team/leakspok"
	"github.com/gofiber/fiber/v2"
)

// RequestBody defines the structure of the request body
type RequestBody struct {
	Data string `json:"data"`
}

func main() {
	// Fiber instance
	app := fiber.New()

	// Routes
	app.Get("/", hello)
	// curl  -X POST http://127.0.0.1:3000/check_pii -H "Content-Type: application/json" -d '{"data": "PIIXXXXXX"}'
	app.Post("/redact_pii", redactPII)

	app.Post("/check_pii", checkPII)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

func createRuleSet() leakspok.RuleSet {

	cpfRule := leakspok.Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      leakspok.CPF(),
		Anonymize:   true,
		AnonymizeOptions: leakspok.AnonymizeOptions{
			Strategy:        leakspok.REDACT,
			AnonymizeString: "[CPF_REDACTED]",
		},
	}

	cnpjRule := leakspok.Rule{
		Name:        "brazilian_CNPJ",
		Description: "Brazilian CNPJ",
		Severity:    3,
		Filter:      leakspok.CNPJ(),
	}

	emailRule := leakspok.Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      leakspok.Email(),
		Anonymize:   true,
		AnonymizeOptions: leakspok.AnonymizeOptions{
			Strategy:        leakspok.MASK,
			AnonymizeString: "*",
			AnonymizeLength: 10,
		},
	}

	return leakspok.RuleSet{
		"c_number":    cpfRule,
		"cnpj_number": cnpjRule,
		"email":       emailRule,
	}
}

// Handler
func hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World 👋!")
}

// redactPII redacts PII information passed on body
func redactPII(c *fiber.Ctx) error {

	var body RequestBody

	// Parse the JSON body into the RequestBody struct
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Cannot parse JSON",
		})
	}

	rules := createRuleSet()
	t := leakspok.NewStringTester(rules)

	result, hasFindings := t.AnonymizeFindings(body.Data)

	if !hasFindings {
		return c.JSON(fiber.Map{
			"message": "No PII found",
		})
	}

	return c.JSON(result)
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
