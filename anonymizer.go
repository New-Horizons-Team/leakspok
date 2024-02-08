package leakspok

// AnonymizeStrategy defines the strategy for anonymizing a finding
type AnonymizeStrategy int

const (
	REDACT AnonymizeStrategy = iota
	MASK
)

// AnonymizeOptions defines the options for anonymizing a finding
type AnonymizeOptions struct {
	Strategy        AnonymizeStrategy
	AnonymizeString string
	AnonymizeLength int
}
