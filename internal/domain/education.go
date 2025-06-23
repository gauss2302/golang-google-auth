package domain

import (
	"fmt"
	"strings"
)

type Education struct {
	Institution string `json:"institution"`
	Location    string `json:"location"`
	Degree      string `json:"degree"`
	Field       string `json:"field"`
	StartDate   string `json:"start_date"` // Format: YYYY-MM-DD
	EndDate     string `json:"end_date"`   // Format: YYYY-MM-DD or "Present"
	Description string `json:"description"`
	GPA         string `json:"gpa,omitempty"`
}

func (e *Education) Validate() error {
	vb := NewValidationBuilder[*Education]()

	// Required fields with security sanitization
	vb.Field("institution", e.Institution).
		Required().
		String().
		NotEmpty().
		MaxLength(200).
		SecureSanitize()

	vb.Field("degree", e.Degree).
		Required().
		String().
		NotEmpty().
		MaxLength(200).
		SecureSanitize()

	vb.Field("start_date", e.StartDate).
		Required().
		Date().
		ISO8601()

	// Optional fields validation
	if e.Location != "" {
		vb.Field("location", e.Location).
			String().
			MaxLength(200).
			SecureSanitize()
	}

	if e.Field != "" {
		vb.Field("field", e.Field).
			String().
			MaxLength(200).
			SecureSanitize()
	}

	// End date validation with special handling for "Present"
	if e.EndDate != "" {
		if e.EndDate == "Present" {
			// "Present" is valid, no further validation needed
		} else {
			vb.Field("end_date", e.EndDate).
				Date().
				ISO8601().
				After(e.StartDate)
		}
	}

	if e.Description != "" {
		vb.Field("description", e.Description).
			String().
			MaxLength(1000).
			SecureSanitize()
	}

	if e.GPA != "" {
		vb.Field("gpa", e.GPA).
			String().
			Pattern(`^\d+\.?\d*$`, "GPA must be a valid number (e.g., 3.5, 4.0)")
	}

	return vb.Build()
}

func (e *Education) BeforeSave() {
	sanitizer := NewSecuritySanitizer()

	// Trim whitespace and sanitize HTML content
	e.Institution = strings.TrimSpace(sanitizer.SanitizeString(e.Institution))
	e.Location = strings.TrimSpace(sanitizer.SanitizeString(e.Location))
	e.Degree = strings.TrimSpace(sanitizer.SanitizeString(e.Degree))
	e.Field = strings.TrimSpace(sanitizer.SanitizeString(e.Field))

	// Date fields don't need HTML sanitization, just trim
	e.StartDate = strings.TrimSpace(e.StartDate)
	e.EndDate = strings.TrimSpace(e.EndDate)

	// Description and GPA
	e.Description = strings.TrimSpace(sanitizer.SanitizeString(e.Description))
	e.GPA = strings.TrimSpace(e.GPA)
}

func (e *Education) ToJSON() ([]byte, error) {
	return MarshalJSON(e)
}

func (e *Education) FromJSON(data []byte) error {
	return UnmarshalJSON(data, e)
}

// Additional helper methods for Education

// IsCompleted returns true if the education has ended (not "Present")
func (e *Education) IsCompleted() bool {
	return e.EndDate != "" && e.EndDate != "Present"
}

// GetDuration returns a human-readable duration string
func (e *Education) GetDuration() string {
	if e.EndDate == "Present" || e.EndDate == "" {
		return e.StartDate + " - Present"
	}
	return e.StartDate + " - " + e.EndDate
}

// HasGPA returns true if GPA is provided
func (e *Education) HasGPA() bool {
	return strings.TrimSpace(e.GPA) != ""
}

// GetFullDescription returns a formatted description combining degree, field, and institution
func (e *Education) GetFullDescription() string {
	var parts []string

	if e.Degree != "" {
		if e.Field != "" {
			parts = append(parts, e.Degree+" in "+e.Field)
		} else {
			parts = append(parts, e.Degree)
		}
	}

	if e.Institution != "" {
		parts = append(parts, "from "+e.Institution)
	}

	if e.Location != "" {
		parts = append(parts, "("+e.Location+")")
	}

	return strings.Join(parts, " ")
}

// EducationCollection represents a collection of education entries using pointers
type EducationCollection []*Education

func (ec EducationCollection) Validate() error {
	var errors ValidationErrors

	for i, education := range ec {
		if education == nil {
			errors = append(errors, NewValidationError(
				fmt.Sprintf("[%d]", i),
				"education entry cannot be nil",
				ErrInvalidField))
			continue
		}

		// Sanitize before validation
		education.BeforeSave()

		if err := education.Validate(); err != nil {
			if validationErrs, ok := err.(ValidationErrors); ok {
				for _, validationErr := range validationErrs {
					validationErr.Field = fmt.Sprintf("[%d].%s", i, validationErr.Field)
					errors = append(errors, validationErr)
				}
			} else {
				errors = append(errors, NewValidationError(
					fmt.Sprintf("[%d]", i),
					err.Error(),
					ErrInvalidField))
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (ec EducationCollection) BeforeSave() {
	for _, education := range ec {
		if education != nil {
			education.BeforeSave()
		}
	}
}

// ValidateAndSanitize is a convenience method that combines both operations
func (ec EducationCollection) ValidateAndSanitize() error {
	ec.BeforeSave()
	return ec.Validate()
}

// SortByStartDate sorts education entries by start date (newest first)
func (ec EducationCollection) SortByStartDate() {
	// Using a simple bubble sort for demonstration
	// In production, you might want to use sort.Slice
	for i := 0; i < len(ec)-1; i++ {
		for j := i + 1; j < len(ec); j++ {
			if ec[i] != nil && ec[j] != nil {
				// Simple string comparison (works for YYYY-MM-DD format)
				if ec[i].StartDate < ec[j].StartDate {
					ec[i], ec[j] = ec[j], ec[i]
				}
			}
		}
	}
}

// GetCompleted returns only completed education entries
func (ec EducationCollection) GetCompleted() EducationCollection {
	var completed EducationCollection
	for _, edu := range ec {
		if edu != nil && edu.IsCompleted() {
			completed = append(completed, edu)
		}
	}
	return completed
}

// GetCurrent returns education entries that are currently in progress
func (ec EducationCollection) GetCurrent() EducationCollection {
	var current EducationCollection
	for _, edu := range ec {
		if edu != nil && !edu.IsCompleted() {
			current = append(current, edu)
		}
	}
	return current
}

// FilterByInstitution returns education entries from a specific institution
func (ec EducationCollection) FilterByInstitution(institution string) EducationCollection {
	var filtered EducationCollection
	for _, edu := range ec {
		if edu != nil && strings.EqualFold(edu.Institution, institution) {
			filtered = append(filtered, edu)
		}
	}
	return filtered
}

// GetDegreeTypes returns unique degree types in the collection
func (ec EducationCollection) GetDegreeTypes() []string {
	degreeMap := make(map[string]bool)
	var degrees []string

	for _, edu := range ec {
		if edu != nil && edu.Degree != "" {
			if !degreeMap[edu.Degree] {
				degreeMap[edu.Degree] = true
				degrees = append(degrees, edu.Degree)
			}
		}
	}

	return degrees
}

// HasDegreeType checks if the collection contains a specific degree type
func (ec EducationCollection) HasDegreeType(degreeType string) bool {
	for _, edu := range ec {
		if edu != nil && strings.EqualFold(edu.Degree, degreeType) {
			return true
		}
	}
	return false
}

// RemoveNilEntries removes any nil entries from the collection
func (ec *EducationCollection) RemoveNilEntries() {
	filtered := make(EducationCollection, 0, len(*ec))
	for _, edu := range *ec {
		if edu != nil {
			filtered = append(filtered, edu)
		}
	}
	*ec = filtered
}

// AddEducation safely adds an education entry to the collection
func (ec *EducationCollection) AddEducation(education *Education) error {
	if education == nil {
		return NewValidationError("education", "cannot add nil education", ErrInvalidField)
	}

	// Validate before adding
	if err := ValidateAndSanitize(education); err != nil {
		return err
	}

	*ec = append(*ec, education)
	return nil
}

// ToJSON converts the collection to JSON
func (ec EducationCollection) ToJSON() ([]byte, error) {
	return MarshalJSON(ec)
}

// FromJSON parses the collection from JSON
func (ec *EducationCollection) FromJSON(data []byte) error {
	return UnmarshalJSON(data, ec)
}

// Helper function to create a new Education pointer
func NewEducation() *Education {
	return &Education{}
}

// Helper function to create a new EducationCollection
func NewEducationCollection() EducationCollection {
	return make(EducationCollection, 0)
}

// Helper function that works with the existing validation framework
func ValidateAndSanitize(model DomainModel) error {
	model.BeforeSave()
	return model.Validate()
}
