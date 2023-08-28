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

	defaultPhoneRule = Rule{
		Name:        "phone_number",
		Description: "phone number",
		Severity:    3,
		Filter:      Phone(),
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

	defaultBrazilianPIIRule = Rule{
		Name:        "brazilian_PII",
		Description: "Brazilian PII",
		Severity:    3,
		Filter:      BrazilianPII(),
	}

	defaultLinkRule = Rule{
		Name:        "link",
		Description: "link or URL",
		Severity:    1,
		Filter:      Link(),
	}

	defaultSSNRule = Rule{
		Name:        "ssn",
		Description: "social security number",
		Severity:    5,
		Filter:      SSN(),
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

	defaultAddressRule = Rule{
		Name:        "street_address",
		Description: "street address or PO box",
		Severity:    3,
		Filter:      Address(),
	}

	defaultBankInfoRule = Rule{
		Name:        "banking_info",
		Description: "IBAN or ACH routing number",
		Severity:    5,
	}

	defaultUUIDRule = Rule{
		Name:        "uuid",
		Description: "valid UUID (v3,v4,v5) or GUID",
		Severity:    3,
		Filter:      UUID(),
	}

	defaultVINRule = Rule{
		Name:        "vin",
		Description: "vehicle identification number (VIN)",
		Severity:    2,
		Filter:      VIN(),
	}
)
