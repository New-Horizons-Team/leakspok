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
		{"111444777-35", true},
		{"111.44477735", true},
		{"111.444.77735", true},
		{"111.444.777-35", true},
		{`111.444.777-35"`, true},
		{`111.444.777-35"]}`, true},
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
		{"14.380.2000001-21", true},
		{"143802000001-21", true},
		{"14.380.2000001-21", true},
		{"14380200/000121", true},
		{`14380200/000121"`, true},
		{`14380200/000121"]}`, true},
		{`14380200/000122"`, false},
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

func TestMatchIP(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"192.168.0.1", true},
		{"10.0.1.9", true},
		{"109.200.3.90", true},
		// TODO {"109.200.3.260", false},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"2001:0db8:85a3::8a2e:0370:7334", true},
		{"2001:::::0370:7334", true},
		{`2001:::::0370:7334"`, true},
		{`2001:::::0370:7334"]}`, true},
		{"", false},
	}

	for _, test := range tests {
		got := matchip(test.input)
		if got != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}
	}
}

func TestMatchEmail(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"joaosilva@gmail.com", true},
		{"joaosilva@mail.ru", true},
		{"joaosilva@ifood.com.br", true},
		{"joao.silva@ifood.com.br", true},
		{"joao.silva@@ifood.com.br", false},
		{`joao.silva@ifood.com.br"`, true},
		{`joao.silva@ifood.com.br"]}`, true},
		{"", false},
	}

	for _, test := range tests {
		got := matchemail(test.input)
		if got != test.expect {
			t.Errorf("For input %q expected %v but got %v", test.input, test.expect, got)
		}
	}
}
