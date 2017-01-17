package jwt

import (
	"errors"
	"fmt"
)

// ErrKey specific error related to a key
type ErrKey interface {
	Error() string
	Key() interface{}
}

// Error constants
var (
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")
)

// ErrInvalidKey error used when key could not be validated
type ErrInvalidKey struct {
	key interface{}
}

// Key returns the invalid key
func (e ErrInvalidKey) Key() interface{} {
	return e.key
}

// Returns the formatted error with the invalid key
func (e ErrInvalidKey) Error() string {
	return fmt.Sprintf("Key is invalid: %#v", e.key)
}

// ErrInvalidKeyType error used when key could not be validated
type ErrInvalidKeyType struct {
	key interface{}
}

// Key returns the invalid key
func (e ErrInvalidKeyType) Key() interface{} {
	return e.key
}

// Returns the formatted error with the invalid key
func (e ErrInvalidKeyType) Error() string {
	return fmt.Sprintf("Key is of invalid type: %#v", e.key)
}

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors
	ValidationErrorAudience      // AUD validation failed
	ValidationErrorExpired       // EXP validation failed
	ValidationErrorIssuedAt      // IAT validation failed
	ValidationErrorIssuer        // ISS validation failed
	ValidationErrorNotValidYet   // NBF validation failed
	ValidationErrorID            // JTI validation failed
	ValidationErrorClaimsInvalid // Generic claims validation error
)

// NewValidationError helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError the error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}
