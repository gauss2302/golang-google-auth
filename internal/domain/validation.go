package domain

import (
	"encoding/json"
	"fmt"
	"github.com/microcosm-cc/bluemonday"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Validation error types
type ValidationErrorType string

const (
	ErrRequired     ValidationErrorType = "required"
	ErrInvalidField ValidationErrorType = "invalid_field"
	ErrDateRange    ValidationErrorType = "date_range"
	ErrInvalidURL   ValidationErrorType = "invalid_url"
	ErrInvalidEmail ValidationErrorType = "invalid_email"
	ErrMinLength    ValidationErrorType = "min_length"
	ErrMaxLength    ValidationErrorType = "max_length"
	ErrInvalidEnum  ValidationErrorType = "invalid_enum"
	ErrXSSDetected  ValidationErrorType = "xss_detected"
)

// ValidationError represents a single field validation error
type ValidationError struct {
	Field   string              `json:"field"`
	Message string              `json:"message"`
	Type    ValidationErrorType `json:"type"`
	Value   interface{}         `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

func NewValidationError(field, message string, errType ValidationErrorType) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
		Type:    errType,
	}
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("validation failed with %d errors", len(e))
}

func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

func (e ValidationErrors) GetFieldErrors(field string) []ValidationError {
	var errors []ValidationError
	for _, err := range e {
		if err.Field == field {
			errors = append(errors, err)
		}
	}
	return errors
}

// Core interfaces using generics
type Validator interface {
	Validate() error
}

type Sanitizer interface {
	BeforeSave()
}

type JSONMarshaler interface {
	ToJSON() ([]byte, error)
	FromJSON(data []byte) error
}

type DomainModel interface {
	Validator
	Sanitizer
	JSONMarshaler
}

// Generic validator interface
type GenericValidator[T any] interface {
	Validate(value T) error
}

// Security sanitizer using Blue Monday
type SecuritySanitizer struct {
	policy *bluemonday.Policy
}

func NewSecuritySanitizer() *SecuritySanitizer {
	// Create a strict policy for user content
	policy := bluemonday.StrictPolicy()

	return &SecuritySanitizer{
		policy: policy,
	}
}

func NewUGCSanitizer() *SecuritySanitizer {
	// More permissive policy for rich content
	policy := bluemonday.UGCPolicy()

	return &SecuritySanitizer{
		policy: policy,
	}
}

func (s *SecuritySanitizer) SanitizeString(input string) string {
	return s.policy.Sanitize(input)
}

func (s *SecuritySanitizer) SanitizeStrings(inputs ...string) []string {
	result := make([]string, len(inputs))
	for i, input := range inputs {
		result[i] = s.policy.Sanitize(input)
	}
	return result
}

// Validation builder with generics support
type ValidationBuilder[T any] struct {
	errors    ValidationErrors
	sanitizer *SecuritySanitizer
}

func NewValidationBuilder[T any]() *ValidationBuilder[T] {
	return &ValidationBuilder[T]{
		errors:    make(ValidationErrors, 0),
		sanitizer: NewSecuritySanitizer(),
	}
}

func NewValidationBuilderWithSanitizer[T any](sanitizer *SecuritySanitizer) *ValidationBuilder[T] {
	return &ValidationBuilder[T]{
		errors:    make(ValidationErrors, 0),
		sanitizer: sanitizer,
	}
}

func (vb *ValidationBuilder[T]) Field(field string, value interface{}) *FieldValidator[T] {
	return &FieldValidator[T]{
		builder: vb,
		field:   field,
		value:   value,
	}
}

func (vb *ValidationBuilder[T]) Build() error {
	if len(vb.errors) > 0 {
		return vb.errors
	}
	return nil
}

func (vb *ValidationBuilder[T]) addError(field, message string, errType ValidationErrorType, value interface{}) {
	vb.errors = append(vb.errors, ValidationError{
		Field:   field,
		Message: message,
		Type:    errType,
		Value:   value,
	})
}

// Generic field validator
type FieldValidator[T any] struct {
	builder *ValidationBuilder[T]
	field   string
	value   interface{}
}

func (fv *FieldValidator[T]) Required() *FieldValidator[T] {
	if fv.isEmpty() {
		fv.builder.addError(fv.field, fv.field+" is required", ErrRequired, fv.value)
	}
	return fv
}

func (fv *FieldValidator[T]) String() *StringValidator[T] {
	str, ok := fv.value.(string)
	if !ok {
		fv.builder.addError(fv.field, "expected string value", ErrInvalidField, fv.value)
		return &StringValidator[T]{fv, ""}
	}
	return &StringValidator[T]{fv, str}
}

func (fv *FieldValidator[T]) StringSlice() *StringSliceValidator[T] {
	slice, ok := fv.value.([]string)
	if !ok {
		fv.builder.addError(fv.field, "expected string slice value", ErrInvalidField, fv.value)
		return &StringSliceValidator[T]{fv, nil}
	}
	return &StringSliceValidator[T]{fv, slice}
}

func (fv *FieldValidator[T]) Date() *DateValidator[T] {
	str, ok := fv.value.(string)
	if !ok {
		fv.builder.addError(fv.field, "expected string date value", ErrInvalidField, fv.value)
		return &DateValidator[T]{fv, ""}
	}
	return &DateValidator[T]{fv, str}
}

func (fv *FieldValidator[T]) URL() *FieldValidator[T] {
	if str, ok := fv.value.(string); ok && str != "" {
		if _, err := url.ParseRequestURI(str); err != nil {
			fv.builder.addError(fv.field, "invalid URL format", ErrInvalidURL, fv.value)
		}
	}
	return fv
}

func (fv *FieldValidator[T]) Email() *FieldValidator[T] {
	if str, ok := fv.value.(string); ok && str != "" {
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(str) {
			fv.builder.addError(fv.field, "invalid email format", ErrInvalidEmail, fv.value)
		}
	}
	return fv
}

func (fv *FieldValidator[T]) OneOf(values ...string) *FieldValidator[T] {
	if str, ok := fv.value.(string); ok && str != "" {
		for _, v := range values {
			if str == v {
				return fv
			}
		}
		fv.builder.addError(fv.field, fmt.Sprintf("must be one of: %v", values), ErrInvalidEnum, fv.value)
	}
	return fv
}

func (fv *FieldValidator[T]) SecureSanitize() *FieldValidator[T] {
	if str, ok := fv.value.(string); ok && str != "" {
		sanitized := fv.builder.sanitizer.SanitizeString(str)
		if sanitized != str {
			fv.builder.addError(fv.field, "content contains potentially unsafe HTML", ErrXSSDetected, fv.value)
		}
	}
	return fv
}

func (fv *FieldValidator[T]) isEmpty() bool {
	if fv.value == nil {
		return true
	}

	v := reflect.ValueOf(fv.value)
	switch v.Kind() {
	case reflect.String:
		return strings.TrimSpace(v.String()) == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.Ptr:
		return v.IsNil()
	default:
		return false
	}
}

// String validator with generics
type StringValidator[T any] struct {
	*FieldValidator[T]
	value string
}

func (sv *StringValidator[T]) MinLength(min int) *StringValidator[T] {
	if len(strings.TrimSpace(sv.value)) < min {
		sv.builder.addError(sv.field, fmt.Sprintf("minimum length is %d characters", min), ErrMinLength, sv.value)
	}
	return sv
}

func (sv *StringValidator[T]) MaxLength(max int) *StringValidator[T] {
	if len(sv.value) > max {
		sv.builder.addError(sv.field, fmt.Sprintf("maximum length is %d characters", max), ErrMaxLength, sv.value)
	}
	return sv
}

func (sv *StringValidator[T]) NotEmpty() *StringValidator[T] {
	if strings.TrimSpace(sv.value) == "" {
		sv.builder.addError(sv.field, sv.field+" cannot be empty", ErrRequired, sv.value)
	}
	return sv
}

func (sv *StringValidator[T]) Pattern(pattern string, message string) *StringValidator[T] {
	if sv.value != "" {
		regex := regexp.MustCompile(pattern)
		if !regex.MatchString(sv.value) {
			sv.builder.addError(sv.field, message, ErrInvalidField, sv.value)
		}
	}
	return sv
}

func (sv *StringValidator[T]) SecureSanitize() *StringValidator[T] {
	if sv.value != "" {
		sanitized := sv.builder.sanitizer.SanitizeString(sv.value)
		if sanitized != sv.value {
			sv.builder.addError(sv.field, "content contains potentially unsafe HTML", ErrXSSDetected, sv.value)
		}
	}
	return sv
}

// String slice validator
type StringSliceValidator[T any] struct {
	*FieldValidator[T]
	value []string
}

func (ssv *StringSliceValidator[T]) MinLength(min int) *StringSliceValidator[T] {
	if len(ssv.value) < min {
		ssv.builder.addError(ssv.field, fmt.Sprintf("minimum %d items required", min), ErrMinLength, ssv.value)
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) MaxLength(max int) *StringSliceValidator[T] {
	if len(ssv.value) > max {
		ssv.builder.addError(ssv.field, fmt.Sprintf("maximum %d items allowed", max), ErrMaxLength, ssv.value)
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) EachMinLength(min int) *StringSliceValidator[T] {
	for i, item := range ssv.value {
		if len(strings.TrimSpace(item)) < min {
			ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i),
				fmt.Sprintf("minimum length is %d characters", min), ErrMinLength, item)
		}
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) EachMaxLength(max int) *StringSliceValidator[T] {
	for i, item := range ssv.value {
		if len(item) > max {
			ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i),
				fmt.Sprintf("maximum length is %d characters", max), ErrMaxLength, item)
		}
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) EachSecureSanitize() *StringSliceValidator[T] {
	for i, item := range ssv.value {
		if item != "" {
			sanitized := ssv.builder.sanitizer.SanitizeString(item)
			if sanitized != item {
				ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i),
					"content contains potentially unsafe HTML", ErrXSSDetected, item)
			}
		}
	}
	return ssv
}

// Date validator with generics
type DateValidator[T any] struct {
	*FieldValidator[T]
	value string
}

func (dv *DateValidator[T]) Format(format string) *DateValidator[T] {
	if dv.value != "" {
		if _, err := time.Parse(format, dv.value); err != nil {
			dv.builder.addError(dv.field, fmt.Sprintf("invalid date format (expected %s)", format), ErrInvalidField, dv.value)
		}
	}
	return dv
}

func (dv *DateValidator[T]) ISO8601() *DateValidator[T] {
	return dv.Format("2006-01-02")
}

func (dv *DateValidator[T]) After(otherDateStr string) *DateValidator[T] {
	if dv.value != "" && otherDateStr != "" {
		date, err1 := time.Parse("2006-01-02", dv.value)
		otherDate, err2 := time.Parse("2006-01-02", otherDateStr)

		if err1 == nil && err2 == nil && !date.After(otherDate) {
			dv.builder.addError(dv.field, "date must be after the reference date", ErrDateRange, dv.value)
		}
	}
	return dv
}

func (dv *DateValidator[T]) Before(otherDateStr string) *DateValidator[T] {
	if dv.value != "" && otherDateStr != "" {
		date, err1 := time.Parse("2006-01-02", dv.value)
		otherDate, err2 := time.Parse("2006-01-02", otherDateStr)

		if err1 == nil && err2 == nil && !date.Before(otherDate) {
			dv.builder.addError(dv.field, "date must be before the reference date", ErrDateRange, dv.value)
		}
	}
	return dv
}

func (dv *DateValidator[T]) OrValue(allowedValue string) *DateValidator[T] {
	if dv.value == allowedValue {
		return dv
	}
	return dv
}

// Generic sanitizer
type GenericSanitizer[T DomainModel] struct {
	sanitizer *SecuritySanitizer
}

func NewGenericSanitizer[T DomainModel]() *GenericSanitizer[T] {
	return &GenericSanitizer[T]{
		sanitizer: NewSecuritySanitizer(),
	}
}

func (gs *GenericSanitizer[T]) SanitizeModel(model T) T {
	model.BeforeSave()
	return model
}

func (gs *GenericSanitizer[T]) SanitizeCollection(models []T) []T {
	for i := range models {
		models[i].BeforeSave()
	}
	return models
}

// Generic validation service
type ValidationService[T DomainModel] struct {
	sanitizer *GenericSanitizer[T]
}

func NewValidationService[T DomainModel]() *ValidationService[T] {
	return &ValidationService[T]{
		sanitizer: NewGenericSanitizer[T](),
	}
}

func (vs *ValidationService[T]) ValidateModel(model T) error {
	model.BeforeSave()
	return model.Validate()
}

func (vs *ValidationService[T]) ValidateCollection(models []T) error {
	var errors ValidationErrors

	for i, model := range models {
		model.BeforeSave()
		if err := model.Validate(); err != nil {
			if validationErrs, ok := err.(ValidationErrors); ok {
				for _, validationErr := range validationErrs {
					validationErr.Field = fmt.Sprintf("[%d].%s", i, validationErr.Field)
					errors = append(errors, validationErr)
				}
			} else {
				errors = append(errors, NewValidationError(fmt.Sprintf("[%d]", i), err.Error(), ErrInvalidField))
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// JSON utilities
func MarshalJSON[T any](v T) ([]byte, error) {
	return json.Marshal(v)
}

func UnmarshalJSON[T any](data []byte, v *T) error {
	return json.Unmarshal(data, v)
}
