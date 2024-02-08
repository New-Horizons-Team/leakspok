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

	DefaultCPFRule = Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      CPF(),
	}

	DefaultCNPJRule = Rule{
		Name:        "brazilian_CNPJ",
		Description: "Brazilian CNPJ",
		Severity:    3,
		Filter:      CNPJ(),
	}

	DefaultLinkRule = Rule{
		Name:        "link",
		Description: "link or URL",
		Severity:    1,
		Filter:      Link(),
	}

	DefaultEmailRule = Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      Email(),
	}

	DefaultIPRule = Rule{
		Name:        "ip_address",
		Description: "valid IPv4 address",
		Severity:    2,
		Filter:      IPv4(),
	}

	DefaultCreditCardRule = Rule{
		Name:        "credit_card",
		Description: "valid credit card number",
		Severity:    5,
		Filter:      CreditCard(),
	}
)

// DefaultMaskString is used to mask matches. It's useful when should report leaks on security alerts
var DefaultMaskString = "<MASKED>"
var DefaultRedactString = "<REDACTED>"
