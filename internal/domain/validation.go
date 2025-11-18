package domain

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
)

var domainValidator *validator.Validate

func init() {
	domainValidator = validator.New()

	domainValidator.RegisterValidation("present_or_date", validatePresentOrDate)
	domainValidator.RegisterStructValidation(educationStructValidation, Education{})
	domainValidator.RegisterStructValidation(experienceStructValidation, Experience{})
}

func validatePresentOrDate(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true
	}
	if value == "Present" {
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

func formatValidationErrors(prefix string, err error) error {
	if err == nil {
		return nil
	}

	if validationErrs, ok := err.(validator.ValidationErrors); ok {
		return fmt.Errorf("%s: %w", prefix, validationErrs)
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

var (
	validatorOnce sync.Once
	validatorInst *validator.Validate
)

// getValidator lazily initializes and returns a shared validator instance with custom rules.
func getValidator() *validator.Validate {
	validatorOnce.Do(func() {
		validatorInst = validator.New()
		// Allow "Present" end dates while still validating real dates.
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

// JSON utilities
func MarshalJSON[T any](v T) ([]byte, error) {
	return json.Marshal(v)
}

	return fmt.Errorf("%s: %w", prefix, err)
}
