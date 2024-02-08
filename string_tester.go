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

// Find creates a new default StringTesterResult object with all default rules included
func (t *StringTester) Find(s []string) (StringTesterResult, error) {
	matched := false
	results := make(map[string]bool)

	for _, rule := range t.Rules {
		for _, str := range s {
			for _, x := range strings.Fields(str) {

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

func replaceFirstNCharsOfSubstring(original string, substring string, n int, replacement string) string {
	index := strings.Index(original, substring)
	if index == -1 {
		// Substring not found
		return original
	}

	// Calculate the end index of the substring
	endIndex := index + len(substring)
	if n > len(substring) {
		// Limit n to the length of the substring
		n = len(substring)
	}

	// Concatenate the parts: before the substring, modified substring, and after the substring
	return original[:index] + strings.Repeat(replacement, n) + original[index+n:endIndex] + original[endIndex:]
}

// AnonymizeFindings anonymizes all matches within the rules
func (t *StringTester) AnonymizeFindings(s string) (string, bool) {
	matched := false
	hasFindings := false

	for _, rule := range t.Rules {
		for _, x := range strings.Fields(s) {
			matched = rule.Filter(x)
			if matched {
				if rule.Anonymize {
					// REDACT first
					if rule.AnonymizeOptions.Strategy == REDACT {
						s = strings.ReplaceAll(s, x, rule.AnonymizeOptions.AnonymizeString)
					}
					// MASK second
					if rule.AnonymizeOptions.Strategy == MASK && len(x) > rule.AnonymizeOptions.AnonymizeLength {
						// Mask the first n characters of the substring
						s = replaceFirstNCharsOfSubstring(s, x, rule.AnonymizeOptions.AnonymizeLength, rule.AnonymizeOptions.AnonymizeString)
					}
					hasFindings = true
				}
			}
		}
	}

	return s, hasFindings
}

// MaskFindings masks all matches within the rules
func (t *StringTester) MaskFindings(s string) string {
	matched := false
	var matchedWords []string

	for _, rule := range t.Rules {
		for _, x := range strings.Fields(s) {
			matched = rule.Filter(x)
			if matched {
				matchedWords = append(matchedWords, x)
			}
		}
	}

	// Replace all matched words
	for _, word := range matchedWords {
		s = strings.ReplaceAll(s, word, DefaultMaskString)
	}

	return s
}
