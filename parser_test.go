package leakspok

import (
	"testing"
)

func TestMatchTestCreditCard(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"4242424242424242", true},
		{"4012888888881881", true},
		{"1234567890123456", false},
		{"", false},
	}

	for _, test := range tests {
		got := matchtestcreditcard(test.input)
		if got != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}
	}
}

func TestMatchCPF(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"11144477735", true},
		{"11144477734", false},
		{"", false},
	}

	for _, test := range tests {
		got := matchCPF(test.input)
		if got != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}
	}
}

func TestMatchCNPJ(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"11.444.777/0001-61", true},
		{"14.380.200/0001-21", true},
		{"11.444.777/0001-60", false},
		{"", false},
	}

	for _, test := range tests {
		got := matchCNPJ(test.input)
		if got != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}
	}
}
