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
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking 111.444.77735, xpto"}],
                 "temperature": 0.1}'`, true},
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

// TestRedactCPF tests the redaction of CPF numbers
func TestRedactCPF(t *testing.T) {
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

	tests := []struct {
		input    string
		expected string
		isLeak   bool
	}{
		{`" \n216.187.210-97"`,
			`" \n` + cpfRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \r216.187.210-97"`,
			`" \r` + cpfRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \t216.187.210-97"`,
			`" \t` + cpfRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \n216.187.210-97\n"`,
			`" \n` + cpfRule.AnonymizeOptions.AnonymizeString + `\n"`,
			true},
		{`" \\216.187.210-97\\\"\\n\"}]"`,
			`" \\` + cpfRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}]"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"216.187.210-97\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"` +
				cpfRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"216.187.210-97\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"` +
				cpfRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"Unable to access the notebook "/Workspace/Users "216.187.210-97" stocks_information"`,
			`"Unable to access the notebook "/Workspace/Users "` + cpfRule.AnonymizeOptions.AnonymizeString + `" stocks_information"`,
			true},
		{`"Unable to access the notebook "/Workspace/Users/216.187.210-97/stocks_information"`,
			`"Unable to access the notebook "/Workspace/Users/` + cpfRule.AnonymizeOptions.AnonymizeString + `/stocks_information"`,
			true},
		{`"Unable to access the notebook "/Workspace/Users/"216.187.210-97"/stocks_information"`,
			`"Unable to access the notebook "/Workspace/Users/"` + cpfRule.AnonymizeOptions.AnonymizeString + `"/stocks_information"`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking '111444777-35" abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking '` + cpfRule.AnonymizeOptions.AnonymizeString + `" abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,111444777-35,,,,, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,` + cpfRule.AnonymizeOptions.AnonymizeString + `,,,,, abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,111444777-35"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,` + cpfRule.AnonymizeOptions.AnonymizeString + `"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,111444777-35'"],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,` + cpfRule.AnonymizeOptions.AnonymizeString + `'"],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,111444777-351,,,,, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing cpf leaking ,,,,111444777-351,,,,, abc"}],
                 "temperature": 0.1}'`,
			false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"content": "Say this: my cpf is 383.413.710-30"}"role": "user"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"content": "Say this: my cpf is ` + cpfRule.AnonymizeOptions.AnonymizeString + `"}"role": "user"}],
                 "temperature": 0.1}'`,
			true},
	}

	leakspokTester := NewStringTester(rules)

	for _, test := range tests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if got != test.expected {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.expected, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, cpfRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q expected find %v in %v", test.input, cpfRule.AnonymizeOptions.AnonymizeString, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if got != test.expected {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.expected, got)
			}

			// Not leaked: the REDACT string is in the string (not expected)
			if strings.Contains(got, cpfRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, cpfRule.AnonymizeOptions.AnonymizeString, got)
			}
		}
	}
}

// TestRedactEmail tests the redaction of email addresses
func TestRedactEmail(t *testing.T) {
	emailRule := Rule{
		Name:        "email_address",
		Description: "Email Address",
		Severity:    3,
		Filter:      Email(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        REDACT,
			AnonymizeString: "[EMAIL_REDACTED]",
		},
	}
	rules := RuleSet{
		"email_address": emailRule,
	}

	tests := []struct {
		input    string
		expected string
		isLeak   bool
	}{
		{`" \nandre.zina@gmail.com"`,
			`" \n` + emailRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \randre.zina@gmail.com"`,
			`" \r` + emailRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \tandre.zina@gmail.com"`,
			`" \t` + emailRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \nandre.zina@gmail.com\n"`,
			`" \n` + emailRule.AnonymizeOptions.AnonymizeString + `\n"`,
			true},
		{`" \\jhon.doe@gmail.com\\\"\\n\"}]"`,
			`" \\` + emailRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}]"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"jhon.doe@gmail.com\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"` +
				emailRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"jhon.doe@gmail.com\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"` +
				emailRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"Unable to access the notebook "/Workspace/Users "jhon.doe@gmail.com" stocks_information"`,
			`"Unable to access the notebook "/Workspace/Users "` + emailRule.AnonymizeOptions.AnonymizeString + `" stocks_information"`,
			true},
		{`Unable to access the notebook "/Workspace/Users/"john.doe@ifood.com.br"/stocks_information"`,
			`Unable to access the notebook "/Workspace/Users/"` + emailRule.AnonymizeOptions.AnonymizeString +
				`"/stocks_information"`,
			true,
		},
		{`Unable to access the notebook "/Workspace/Users/john.doe@ifood.com.br/stocks_information"`,
			`Unable to access the notebook "/Workspace/Users/` + emailRule.AnonymizeOptions.AnonymizeString +
				`/stocks_information"`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking "joao.silva@gmail.com" aa"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking "` + emailRule.AnonymizeOptions.AnonymizeString + `" aa"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking 'joao.silva@gmail.com"" abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking '` + emailRule.AnonymizeOptions.AnonymizeString + `"" abc"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking joao.silva@gmail.com, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ` + emailRule.AnonymizeOptions.AnonymizeString + `, abc"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,joao.silva@gmail.com,,,,!!!! abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,` + emailRule.AnonymizeOptions.AnonymizeString + `,,,,!!!! abc"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,!!!;!?????joao@teste.br,,,,!!!!????? abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,!!!;!?????` + emailRule.AnonymizeOptions.AnonymizeString + `,,,,!!!!????? abc"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking '}joao@teste.br"{} abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking '}` + emailRule.AnonymizeOptions.AnonymizeString + `"{} abc"}],
                 "temperature": 0.1}'`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,!!!;!?????joao@teste,,,,!!!!????? abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking ,!!!;!?????joao@teste,,,,!!!!????? abc"}],
                 "temperature": 0.1}'`,
			false,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking,joao.test@gmail.com "}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking,` + emailRule.AnonymizeOptions.AnonymizeString + ` "}],
                 "temperature": 0.1}'`,
			true,
		},
	}

	leakspokTester := NewStringTester(rules)

	for _, test := range tests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if got != test.expected {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.expected, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, emailRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q expected find %v in %v", test.input, emailRule.AnonymizeOptions.AnonymizeString, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if got != test.expected {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.expected, got)
			}

			// Not leaked: the REDACT string is in the string (not expected)
			if strings.Contains(got, emailRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, emailRule.AnonymizeOptions.AnonymizeString, got)
			}
		}
	}
}

// TestRedactIPAddress tests the redaction of IP addresses
func TestRedactIPAddress(t *testing.T) {
	ipRule := Rule{
		Name:        "ip_address",
		Description: "IP Address",
		Severity:    3,
		Filter:      IPv4(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        REDACT,
			AnonymizeString: "[IP_REDACTED]",
		},
	}
	rules := RuleSet{
		"ip_address": ipRule,
	}

	tests := []struct {
		input    string
		expected string
		isLeak   bool
	}{
		{`" \n180.112.90.22"`,
			`" \n` + ipRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \r180.112.90.22"`,
			`" \r` + ipRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \t180.112.90.22"`,
			`" \t` + ipRule.AnonymizeOptions.AnonymizeString + `"`,
			true},
		{`" \n180.112.90.22\n"`,
			`" \n` + ipRule.AnonymizeOptions.AnonymizeString + `\n"`,
			true},
		{`" \\180.112.90.22\\\"\\n\"}]"`,
			`" \\` + ipRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}]"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"180.112.90.22\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\"` +
				ipRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"180.112.90.22\\\"\\n\"}], \"temperature\": 0.7}"`,
			`"{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"\\n\\\"` +
				ipRule.AnonymizeOptions.AnonymizeString + `\\\"\\n\"}], \"temperature\": 0.7}"`,
			true},
		{`"Unable to access the notebook "/Workspace/Users "180.112.90.22" stocks_information"`,
			`"Unable to access the notebook "/Workspace/Users "` + ipRule.AnonymizeOptions.AnonymizeString + `" stocks_information"`,
			true},
		{`Unable to access the notebook "/Workspace/Users/"180.112.90.22"/stocks_information"`,
			`Unable to access the notebook "/Workspace/Users/"` + ipRule.AnonymizeOptions.AnonymizeString +
				`"/stocks_information"`,
			true,
		},
		{`Unable to access the notebook "/Workspace/Users/180.112.90.22/stocks_information"`,
			`Unable to access the notebook "/Workspace/Users/` + ipRule.AnonymizeOptions.AnonymizeString +
				`/stocks_information"`,
			true,
		},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking 180.112.90.22 abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ` + ipRule.AnonymizeOptions.AnonymizeString + ` abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,180.112.90.22,, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,` + ipRule.AnonymizeOptions.AnonymizeString + `,, abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,'180.112.90.22"{ abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,'` + ipRule.AnonymizeOptions.AnonymizeString + `"{ abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;180.112.90.22,????, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;` + ipRule.AnonymizeOptions.AnonymizeString + `,????, abc"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;180.112.90.22"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;` + ipRule.AnonymizeOptions.AnonymizeString + `"}],
                 "temperature": 0.1}'`,
			true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;999.112.90.999,::????, abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking ,????????;;999.112.90.999,::????, abc"}],
                 "temperature": 0.1}'`,
			false},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking,180.112.90.22 abc"}],
                 "temperature": 0.1}'`,
			`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking,` + ipRule.AnonymizeOptions.AnonymizeString + ` abc"}],
                 "temperature": 0.1}'`,
			true},
	}

	leakspokTester := NewStringTester(rules)

	for _, test := range tests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if got != test.expected {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.expected, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, ipRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q expected find %v in %v", test.input, ipRule.AnonymizeOptions.AnonymizeString, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if got != test.expected {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.expected, got)
			}

			// Not leaked: the REDACT string is in the string (not expected)
			if strings.Contains(got, ipRule.AnonymizeOptions.AnonymizeString) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, ipRule.AnonymizeOptions.AnonymizeString, got)
			}
		}
	}
}

// TestMaskFindings tests the masking of findings
//
//gocyclo:ignore
func TestMaskFindings(t *testing.T) {
	cpfTests := []struct {
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

	ipTests := []struct {
		input  string
		leak   string
		isLeak bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking 180.112.90.22 abc"}],
                 "temperature": 0.1}'`, "180.112.90.22", true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking 1.1.1.1 abc"}],
                 "temperature": 0.1}'`, "1.1.1.1", true},
		{`'{
	 			"model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing IP address leaking 200.123.2.289 abc"}],
                 "temperature": 0.1}'`, "200.123.2.289", false},
	}

	emailTests := []struct {
		input  string
		leak   string
		isLeak bool
	}{
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking joao.silva@gmail.com abc"}],
                 "temperature": 0.1}'`, "joao.silva@gmail.com", true},
		{`'{
                 "model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking j@e.com abc"}],
                 "temperature": 0.1}'`, " j@e.com", true},
		{`'{
	 			"model": "gpt-3.5-turbo",
                 "messages": [{"role": "user", "content": "testing email leaking joao.silva@mail.com.br abc"}],
                 "temperature": 0.1}'`, " joao.silva@mail.com.br", true},
	}

	cpfRule := Rule{
		Name:        "brazilian_CPF",
		Description: "Brazilian CPF",
		Severity:    3,
		Filter:      CPF(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        MASK,
			AnonymizeString: "*",
			AnonymizeLength: 3,
		},
	}

	ipRule := Rule{
		Name:        "ip_address",
		Description: "IP Addresses",
		Severity:    3,
		Filter:      IP(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        MASK,
			AnonymizeString: "*",
			AnonymizeLength: 3,
		},
	}

	emailRule := Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      Email(),
		Anonymize:   true,
		AnonymizeOptions: AnonymizeOptions{
			Strategy:        MASK,
			AnonymizeString: "*",
			AnonymizeLength: 3,
		},
	}

	rules := RuleSet{
		"cpf_rule":   cpfRule,
		"ip_rule":    ipRule,
		"email_rule": emailRule,
	}

	leakspokTester := NewStringTester(rules)

	for _, test := range cpfTests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		expect := strings.Repeat(cpfRule.AnonymizeOptions.AnonymizeString, cpfRule.AnonymizeOptions.AnonymizeLength)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.leak, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, expect) {
				t.Errorf("For input %q expected find %v in %v", test.input, expect, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if !strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.leak, got)
			}

			// Not leaked: the REDACT string is NOT in the string
			if strings.Contains(got, expect) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, expect, got)
			}
		}
	}

	for _, test := range ipTests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		expect := strings.Repeat(ipRule.AnonymizeOptions.AnonymizeString, ipRule.AnonymizeOptions.AnonymizeLength)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.leak, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, expect) {
				t.Errorf("For input %q expected find %v in %v", test.input, expect, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if !strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.leak, got)
			}

			// Not leaked: the REDACT string is NOT in the string
			if strings.Contains(got, expect) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, expect, got)
			}
		}
	}

	for _, test := range emailTests {
		got, _ := leakspokTester.AnonymizeFindings(test.input)

		expect := strings.Repeat(emailRule.AnonymizeOptions.AnonymizeString, emailRule.AnonymizeOptions.AnonymizeLength)

		if test.isLeak {
			// If cpf is in the string, it wasn't masked
			if strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected not find %v in %v", test.input, test.leak, got)
			}

			// If REDACT string is not in the string, it wasn't masked
			if !strings.Contains(got, expect) {
				t.Errorf("For input %q expected find %v in %v", test.input, expect, got)
			}
		} else {
			// Not leaked: the potential leak is still in the string (as expected)
			if !strings.Contains(got, test.leak) {
				t.Errorf("For input %q expected finding %v in %v", test.input, test.leak, got)
			}

			// Not leaked: the REDACT string is NOT in the string
			if strings.Contains(got, expect) {
				t.Errorf("For input %q, it is not expected find %v in %v", test.input, expect, got)
			}
		}
	}
}

// TestFindChainMatchesByBreakingLines tests to find chain matches by breaking lines
// Example:
// "data": "\n\n\n\n<CPF>"}' -> {"cpf_number": true, "cnpj_number": true, "email_address": true, "ip_address": true}
func TestFindChainMatchesByBreakingLines(t *testing.T) {
	rules := RuleSet{}
	leakspokTester := NewStringTester(rules)
	leakspokTester.Rules = []Rule{DefaultCPFRule, DefaultIPRule, DefaultEmailRule, DefaultCNPJRule}

	expected := StringTesterResult{BrazilianCPF: true, BrazilianCNPJ: false, EmailAddress: false, IPAddress: false}

	input := "\n\n111444777-35"
	lines := strings.Split(input, "\n")
	// lines = ["", "", "111444777-35"]
	got, err := leakspokTester.Find(lines)

	if err != nil {
		t.Errorf("For input %q expected %+v but got %+v", input, expected, got)
	}

	if got != expected {
		t.Errorf("For input %q expected %+v but got %+v", input, expected, got)
	}
}
