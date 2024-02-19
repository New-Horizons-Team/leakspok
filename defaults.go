package leakspok

var (
	// DefaultRuleSet provides a rule set of default PII rules
	DefaultRuleSet = RuleSet{
		"cpf_number":    DefaultCPFRule,
		"cnpj_number":   DefaultCNPJRule,
		"email_address": DefaultEmailRule,
		"ip_address":    DefaultIPRule,
		"credit_card":   DefaultCreditCardRule,
	}

	// DefaultCPFRule is a default rule for Brazilian CPF
	DefaultCPFRule = Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      CPF(),
	}

	// DefaultCNPJRule is a default rule for Brazilian CNPJ
	DefaultCNPJRule = Rule{
		Name:        "brazilian_CNPJ",
		Description: "Brazilian CNPJ",
		Severity:    3,
		Filter:      CNPJ(),
	}

	// DefaultEmailRule is a default rule for email address
	DefaultEmailRule = Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      Email(),
	}

	// DefaultIPRule is a default rule for IP address
	DefaultIPRule = Rule{
		Name:        "ip_address",
		Description: "valid IPv4 address",
		Severity:    2,
		Filter:      IPv4(),
	}

	// DefaultCreditCardRule is a default rule for credit card number
	DefaultCreditCardRule = Rule{
		Name:        "credit_card",
		Description: "valid credit card number",
		Severity:    5,
		Filter:      CreditCard(),
	}
)

// DefaultMaskString is used to mask matches. It's useful when should report leaks on security alerts
var DefaultMaskString = "<MASKED>"

// DefaultRedactString is used to redact matches. It's useful when should report leaks on security alerts
var DefaultRedactString = "<REDACTED>"
