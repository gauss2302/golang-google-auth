package domain

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
)

type ValidationErrorType string

const (
	ErrRequired     ValidationErrorType = "required"
	ErrInvalidField ValidationErrorType = "invalid_field"
	ErrMaxLength    ValidationErrorType = "max_length"
	ErrMinLength    ValidationErrorType = "min_length"
	ErrDateRange    ValidationErrorType = "date_range"
	ErrXSSDetected  ValidationErrorType = "xss_detected"
)

type ValidationError struct {
	Field   string              `json:"field"`
	Message string              `json:"message"`
	Type    ValidationErrorType `json:"type"`
	Value   interface{}         `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func NewValidationError(field, message string, errType ValidationErrorType, value ...interface{}) ValidationError {
	var v interface{}
	if len(value) > 0 {
		v = value[0]
	}
	return ValidationError{
		Field:   field,
		Message: message,
		Type:    errType,
		Value:   v,
	}
}

type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}
	parts := make([]string, len(ve))
	for i, err := range ve {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

// DomainModel is implemented by all domain entities that can be validated and sanitized.
type DomainModel interface {
	Validate() error
	BeforeSave()
}

// SecuritySanitizer provides HTML sanitization helpers.
type SecuritySanitizer struct {
	policy *bluemonday.Policy
}

func NewSecuritySanitizer() *SecuritySanitizer {
	return &SecuritySanitizer{policy: bluemonday.StrictPolicy()}
}

func NewUGCSanitizer() *SecuritySanitizer {
	return &SecuritySanitizer{policy: bluemonday.UGCPolicy()}
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

var (
	domainValidator *validator.Validate
	validatorOnce   sync.Once
	validatorInst   *validator.Validate
)

func init() {
	domainValidator = validator.New()
	domainValidator.RegisterValidation("present_or_date", validatePresentOrDate)
	domainValidator.RegisterStructValidation(educationStructValidation, Education{})
	domainValidator.RegisterStructValidation(experienceStructValidation, Experience{})
}

func validatePresentOrDate(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" || value == "Present" {
		return true
	}

	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

func educationStructValidation(sl validator.StructLevel) {
	education := sl.Current().Interface().(Education)

	if education.EndDate == "" || education.EndDate == "Present" {
		return
	}

	start, startErr := time.Parse("2006-01-02", education.StartDate)
	end, endErr := time.Parse("2006-01-02", education.EndDate)
	if startErr != nil || endErr != nil {
		return
	}

	if end.Before(start) {
		sl.ReportError(education.EndDate, "EndDate", "end_date", "after_start", "")
	}
}

func experienceStructValidation(sl validator.StructLevel) {
	experience := sl.Current().Interface().(Experience)

	if experience.EndDate == "" || experience.EndDate == "Present" {
		return
	}

	start, startErr := time.Parse("2006-01-02", experience.StartDate)
	end, endErr := time.Parse("2006-01-02", experience.EndDate)
	if startErr != nil || endErr != nil {
		return
	}

	if end.Before(start) {
		sl.ReportError(experience.EndDate, "EndDate", "end_date", "after_start", "")
	}
}

// Utility to turn go-playground errors into project ValidationErrors with a prefix.
func formatValidationErrors(prefix string, err error) error {
	if err == nil {
		return nil
	}

	if validationErrs, ok := err.(validator.ValidationErrors); ok {
		mapped := make(ValidationErrors, 0, len(validationErrs))
		for _, fieldErr := range validationErrs {
			field := fieldErr.Field()
			if prefix != "" {
				field = prefix + "." + field
			}
			mapped = append(mapped, ValidationError{
				Field:   field,
				Message: formatValidationMessage(fieldErr),
				Type:    ErrInvalidField,
				Value:   fieldErr.Value(),
			})
		}
		return mapped
	}

	return err
}

// ValidationBuilder is a lightweight helper for manual validations.
type ValidationBuilder[T any] struct {
	errors    ValidationErrors
	sanitizer *SecuritySanitizer
}

func NewValidationBuilder[T any]() *ValidationBuilder[T] {
	return &ValidationBuilder[T]{
		sanitizer: NewSecuritySanitizer(),
	}
}

func (vb *ValidationBuilder[T]) Field(field string, value interface{}) *FieldValidator[T] {
	return &FieldValidator[T]{builder: vb, field: field, value: value}
}

func (vb *ValidationBuilder[T]) addError(field, message string, errType ValidationErrorType, value interface{}) {
	vb.errors = append(vb.errors, NewValidationError(field, message, errType, value))
}

func (vb *ValidationBuilder[T]) Build() error {
	if len(vb.errors) == 0 {
		return nil
	}
	return vb.errors
}

type FieldValidator[T any] struct {
	builder *ValidationBuilder[T]
	field   string
	value   interface{}
}

func (fv *FieldValidator[T]) Required() *FieldValidator[T] {
	if fv.isEmpty() {
		fv.builder.addError(fv.field, "field is required", ErrRequired, fv.value)
	}
	return fv
}

func (fv *FieldValidator[T]) String() *StringValidator[T] {
	str, _ := fv.value.(string)
	return &StringValidator[T]{FieldValidator: fv, value: str}
}

func (fv *FieldValidator[T]) StringSlice() *StringSliceValidator[T] {
	values, _ := fv.value.([]string)
	return &StringSliceValidator[T]{FieldValidator: fv, value: values}
}

func (fv *FieldValidator[T]) Date() *DateValidator[T] {
	value, _ := fv.value.(string)
	return &DateValidator[T]{FieldValidator: fv, value: value}
}

func (fv *FieldValidator[T]) URL() *FieldValidator[T] {
	if str, ok := fv.value.(string); ok && str != "" {
		if _, err := url.ParseRequestURI(str); err != nil {
			fv.builder.addError(fv.field, "invalid URL", ErrInvalidField, fv.value)
		}
	}
	return fv
}

func (fv *FieldValidator[T]) Email() *FieldValidator[T] {
	if email, ok := fv.value.(string); ok && email != "" {
		re := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
		if !re.MatchString(email) {
			fv.builder.addError(fv.field, "invalid email address", ErrInvalidField, fv.value)
		}
	}
	return fv
}

func (fv *FieldValidator[T]) OneOf(values ...string) *FieldValidator[T] {
	if val, ok := fv.value.(string); ok && val != "" {
		for _, allowed := range values {
			if val == allowed {
				return fv
			}
		}
		fv.builder.addError(fv.field, fmt.Sprintf("must be one of: %s", strings.Join(values, ", ")), ErrInvalidField, fv.value)
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
	switch v := fv.value.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case []string:
		return len(v) == 0
	case nil:
		return true
	default:
		return false
	}
}

type StringValidator[T any] struct {
	*FieldValidator[T]
	value string
}

func (sv *StringValidator[T]) MaxLength(max int) *StringValidator[T] {
	if len(sv.value) > max {
		sv.builder.addError(sv.field, fmt.Sprintf("maximum length is %d characters", max), ErrMaxLength, sv.value)
	}
	return sv
}

func (sv *StringValidator[T]) NotEmpty() *StringValidator[T] {
	if strings.TrimSpace(sv.value) == "" {
		sv.builder.addError(sv.field, "field cannot be empty", ErrRequired, sv.value)
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
			ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i), fmt.Sprintf("minimum length is %d characters", min), ErrMinLength, item)
		}
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) EachMaxLength(max int) *StringSliceValidator[T] {
	for i, item := range ssv.value {
		if len(item) > max {
			ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i), fmt.Sprintf("maximum length is %d characters", max), ErrMaxLength, item)
		}
	}
	return ssv
}

func (ssv *StringSliceValidator[T]) EachSecureSanitize() *StringSliceValidator[T] {
	for i, item := range ssv.value {
		if item != "" {
			sanitized := ssv.builder.sanitizer.SanitizeString(item)
			if sanitized != item {
				ssv.builder.addError(fmt.Sprintf("%s[%d]", ssv.field, i), "content contains potentially unsafe HTML", ErrXSSDetected, item)
			}
		}
	}
	return ssv
}

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

// getValidator lazily initializes and returns a shared validator instance with custom rules.
func getValidator() *validator.Validate {
	validatorOnce.Do(func() {
		validatorInst = validator.New()
		_ = validatorInst.RegisterValidation("date_or_present", func(fl validator.FieldLevel) bool {
			value := fl.Field().String()
			if value == "" || value == "Present" {
				return true
			}
			_, err := time.Parse("2006-01-02", value)
			return err == nil
		})
	})
	return validatorInst
}

// ValidateStruct validates a struct using go-playground/validator and maps errors into the
// project's ValidationErrors format for consistent error handling.
func ValidateStruct(model interface{}) error {
	if err := getValidator().Struct(model); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			mapped := make(ValidationErrors, 0, len(validationErrors))
			for _, fieldErr := range validationErrors {
				mapped = append(mapped, ValidationError{
					Field:   fieldErr.Field(),
					Message: formatValidationMessage(fieldErr),
					Type:    ErrInvalidField,
					Value:   fieldErr.Value(),
				})
			}
			return mapped
		}
		return err
	}
	return nil
}

func formatValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "field is required"
	case "max":
		return fmt.Sprintf("must not exceed %s", err.Param())
	case "min":
		return fmt.Sprintf("must be at least %s", err.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", err.Param())
	case "datetime":
		return fmt.Sprintf("must match datetime format %s", err.Param())
	case "date_or_present":
		return "must be a valid date (YYYY-MM-DD) or 'Present'"
	default:
		return err.Error()
	}
}

func MarshalJSON[T any](v T) ([]byte, error) {
	return json.Marshal(v)
}
