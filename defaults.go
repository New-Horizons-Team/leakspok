package leakspok

var (
	// DefaultRuleSet provides a rule set of default PII rules
	DefaultRuleSet = RuleSet{
		"cpf_number":    defaultCPFRule,
		"cnpj_number":   defaultCNPJRule,
		"email_address": defaultEmailRule,
		"ip_address":    defaultIPRule,
		"credit_card":   defaultCreditCardRule,
		// "link":           defaultLinkRule,
	}

	defaultCPFRule = Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      CPF(),
	}

	defaultCNPJRule = Rule{
		Name:        "brazilian_CNPJ",
		Description: "Brazilian CNPJ",
		Severity:    3,
		Filter:      CNPJ(),
	}

	defaultLinkRule = Rule{
		Name:        "link",
		Description: "link or URL",
		Severity:    1,
		Filter:      Link(),
	}

	defaultEmailRule = Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      Email(),
	}

	defaultIPRule = Rule{
		Name:        "ip_address",
		Description: "valid IPv4 or IPv6 address",
		Severity:    2,
		Filter:      IP(),
	}

	defaultCreditCardRule = Rule{
		Name:        "credit_card",
		Description: "valid credit card number",
		Severity:    5,
		Filter:      CreditCard(),
	}
)
