package leakspok

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Must sync with the DefaultRuleSet
// TODO: use code generaton for this
type StringTesterResult struct {
	BrazilianCNPJ bool `json:"brazilian_CNPJ"`
	BrazilianCPF  bool `json:"brazilian_CPF"`
	CreditCard    bool `json:"credit_card"`
	EmailAddress  bool `json:"email_address"`
	IPAddress     bool `json:"ip_address"`
}

// Tester defines a test harness for assessment
type StringTester struct {
	Rules []Rule `json:"rules,omitempty" csv:"rules"`
}

// NewEmptyTester returns an empty Test harness with no rules loaded
func NewEmptyStringTester() *StringTester {
	return &StringTester{
		Rules: []Rule{},
	}
}

// NewDefaultTester creates a new default Test harness with all default rules included
func NewDefaultStringTester() *StringTester {
	t := NewEmptyStringTester()
	for _, r := range DefaultRuleSet {
		t.Rules = append(t.Rules, r)
	}
	return t
}

// NewDefaultTester creates a new default Test harness with all default rules included
func (t *StringTester) Find(s []string) (StringTesterResult, error) {
	matched := false
	results := make(map[string]bool)
	//results := StringTesterResult{}

	for _, rule := range t.Rules {
		for _, str := range s {
			for _, x := range strings.Fields(str) {
				matched = rule.Filter(x)
				if matched {
					break
				}
			}
		}

		results[rule.Name] = matched
		//dur := time.Since(ts).Nanoseconds()
		fmt.Println("match: " + rule.Name + " " + strconv.FormatBool(matched))
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
