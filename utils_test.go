package leakspok

import (
	"testing"
)

func TestSumDigit(t *testing.T) {
	tests := []struct {
		s      string
		table  []int
		result int
	}{
		{
			s:      "123",
			table:  []int{1, 2, 3},
			result: 14, // 1*1 + 2*2 + 3*3 = 1 + 4 + 9 = 14
		},
		{
			s:      "12a",
			table:  []int{1, 2, 3},
			result: 5, // 1*1 + 2*2 = 1 + 4 = 5 (the character 'a' is ignored)
		},
		{
			s:      "123",
			table:  []int{1, 2},
			result: 0, // different lengths, so result is 0
		},
	}

	for _, tt := range tests {
		got := sumDigit(tt.s, tt.table)
		if got != tt.result {
			t.Errorf("Expected sumDigit(%q, %v) to be %d, but got %d", tt.s, tt.table, tt.result, got)
		}
	}
}
