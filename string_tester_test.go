package leakspok

import (
	"strings"
	"testing"
)

func TestFindCPF(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-35 abc"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111.444.777-35"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111.444.77735"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111.444.77735 xpto"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-31 abc"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-31"}],
                 "temperature": 0.1}'`, false},
	}

	rules := RuleSet{
		"cpf_number":    DefaultCPFRule,
		"cnpj_number":   DefaultCNPJRule,
		"email_address": DefaultEmailRule,
		"ip_address":    DefaultIPRule,
	}

	leakspokTester := NewStringTester(rules)
	for _, test := range tests {
		lines := strings.Split(test.input, "\n")
		got, err := leakspokTester.Find(lines)
		if err != nil {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}

		if got.BrazilianCPF != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got.BrazilianCPF)
		}
	}
}

func TestFindIP(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 129.12.34.1 abc"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 12.34.1.34"}],
                 "temperature": 0.1}'`, true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 299.34.1.34"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 200.340.1.34"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 200.34.1024.34"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 200.34.124.256"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 4.3.23 date comparing"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 4.03.23 date comparing"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 22::50 ipv6 matching"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 22::50"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 2001:0000:130F:0000:0000:09C0:876A:130B ipv6 matching"}],
                 "temperature": 0.1}'`, false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP leaking 2001:0000:130F:0000:0000:09C0:876A:130B"}],
                 "temperature": 0.1}'`, false},
	}

	rules := RuleSet{
		"cpf_number":    DefaultCPFRule,
		"cnpj_number":   DefaultCNPJRule,
		"email_address": DefaultEmailRule,
		"ip_address":    DefaultIPRule,
	}

	leakspokTester := NewStringTester(rules)
	for _, test := range tests {
		lines := strings.Split(test.input, "\n")
		got, err := leakspokTester.Find(lines)
		if err != nil {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}

		if got.IPAddress != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got.IPAddress)
		}
	}
}

func TestMaskFindings(t *testing.T) {
	tests := []struct {
		input  string
		leak   string
		isLeak bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-35 abc"}],
                 "temperature": 0.1}'`, "111444777-35", true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-34 abc"}],
                 "temperature": 0.1}'`, "111444777-34", false},
	}

	rules := RuleSet{
		"cpf_number":    DefaultCPFRule,
		"cnpj_number":   DefaultCNPJRule,
		"email_address": DefaultEmailRule,
		"ip_address":    DefaultIPRule,
	}

	leakspokTester := NewStringTester(rules)
	for _, test := range tests {
		got := leakspokTester.MaskFindings(test.input)

		if test.isLeak {
			//if cpf is in the string, it wasn't masked
			if strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.leak, got)
			}

			//if default mask (<MASKED>) is not in the string, it wasn't masked
			if !strings.Contains(got, DefaultMaskString) {
				t.Errorf("For input %q expected find %v in %v", test.input, DefaultMaskString, got)
			}
		} else {
			//Not leaked: the potential leak is still in the string (as expected)
			if !strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.leak, got)
			}

			//Not leaked: the default MASK is NOT in the string
			if strings.Contains(got, DefaultMaskString) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, DefaultMaskString, got)
			}
		}
	}
}

func TestRedactCPF(t *testing.T) {
	tests := []struct {
		input  string
		leak   string
		isLeak bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-35 abc"}],
                 "temperature": 0.1}'`, "111444777-35", true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111444777-34 abc"}],
                 "temperature": 0.1}'`, "111444777-34", false},
	}

	cpfRule := Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      CPF(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        REDACT,
			AnonymizeString: "[CPF_REDACTED]",
		},
	}
	rules := RuleSet{
		"cpf_number": cpfRule,
	}

	leakspokTester := NewStringTester(rules)

	for _, test := range tests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		if test.isLeak {
			//if cpf is in the string, it wasn't masked
			if strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.leak, got)
			}

			//if REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, cpfRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q expected find %v in %v", test.input, cpfRule.AnonymizeOptions.AnonymizeString, got)
			}
		} else {
			//Not leaked: the potential leak is still in the string (as expected)
			if !strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.leak, got)
			}

			//Not leaked: the REDACT string is NOT in the string
			if strings.Contains(got, cpfRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, cpfRule.AnonymizeOptions.AnonymizeString, got)
			}
		}
	}
}
