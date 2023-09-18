package leakspok

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StringTesterResult must sync with the DefaultRuleSet
// TODO: use code generation for this
type StringTesterResult struct {
	BrazilianCNPJ bool `json:"brazilian_CNPJ"`
	BrazilianCPF  bool `json:"brazilian_CPF"`
	CreditCard    bool `json:"credit_card"`
	EmailAddress  bool `json:"email_address"`
	IPAddress     bool `json:"ip_address"`
}

// StringTester  defines a test harness for assessment
type StringTester struct {
	Rules []Rule `json:"rules,omitempty"`
}

// NewEmptyStringTester returns an empty StringTester object with no rules loaded
func NewEmptyStringTester() *StringTester {
	return &StringTester{
		Rules: []Rule{},
	}
}

// NewDefaultStringTester creates a new default StringTester object with all default rules included
func NewDefaultStringTester() *StringTester {
	t := NewEmptyStringTester()
	for _, r := range DefaultRuleSet {
		t.Rules = append(t.Rules, r)
	}
	return t
}

// NewStringTester creates a new  StringTester object with all rules included by the user
func NewStringTester(set RuleSet) *StringTester {
	t := NewEmptyStringTester()
	for _, r := range set {
		t.Rules = append(t.Rules, r)
	}
	return t
}

// Find NewDefaultTester creates a new default StringTesterResult object with all default rules included
func (t *StringTester) Find(s []string, removeSpecialChars bool) (StringTesterResult, error) {
	matched := false
	results := make(map[string]bool)

	for _, rule := range t.Rules {
		for _, str := range s {
			for _, x := range strings.Fields(str) {

				//remove unnecessary characters
				if removeSpecialChars {
					replacer := strings.NewReplacer(`"`, "", ".", "", "-", "", `,`, "", `]`, "", `}`, "")
					x = replacer.Replace(x)
				}

				matched = rule.Filter(x)
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}

		results[rule.Name] = matched
	}

	// Unmarshal the JSON data into StringTesterResult
	var testerResult StringTesterResult
	jsonData, err := json.Marshal(results)
	if err != nil {
		return testerResult, err
	}

	err = json.Unmarshal(jsonData, &testerResult)
	if err != nil {
		return testerResult, fmt.Errorf("error on parsing result")
	}

	return testerResult, nil
}
