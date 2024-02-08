package leakspok

// AnonymizeStrategy defines the strategy for anonymizing a finding
type AnonymizeStrategy int

const (
	// REDACT is the strategy for redacting a finding
	REDACT AnonymizeStrategy = iota
	// MASK is the strategy for masking a finding
	MASK
)

// AnonymizeOptions defines the options for anonymizing a finding
type AnonymizeOptions struct {
	Strategy        AnonymizeStrategy
	AnonymizeString string
	AnonymizeLength int
}
