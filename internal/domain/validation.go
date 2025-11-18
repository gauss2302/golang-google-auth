package domain

import (
	"fmt"
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

	return fmt.Errorf("%s: %w", prefix, err)
}
