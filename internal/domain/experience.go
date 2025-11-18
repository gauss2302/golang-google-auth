package domain

import (
	"strings"
	"time"
)

type Experience struct {
	Employer     string   `json:"employer" validate:"required,max=200"`
	JobTitle     string   `json:"title" validate:"required,max=200"`
	Location     string   `json:"location" validate:"omitempty,max=200"`
	StartDate    string   `json:"start_date" validate:"required,datetime=2006-01-02"` // Format: YYYY-MM-DD
	EndDate      string   `json:"end_date" validate:"omitempty,date_or_present"`      // Format: YYYY-MM-DD or "Present"
	Description  string   `json:"description" validate:"omitempty,max=2000"`
	Achievements []string `json:"achievements,omitempty" validate:"max=20,dive,max=500"`
}

func (e *Experience) Validate() error {
	if err := ValidateStruct(e); err != nil {
		return err
	}

	if e.EndDate != "" && e.EndDate != "Present" {
		start, startErr := time.Parse("2006-01-02", e.StartDate)
		end, endErr := time.Parse("2006-01-02", e.EndDate)
		if startErr == nil && endErr == nil && end.Before(start) {
			return ValidationErrors{NewValidationError("end_date", "end_date must be after start_date", ErrDateRange)}
		}
	}

	return nil
}

func (e *Experience) BeforeSave() {
	sanitizer := NewSecuritySanitizer()

	e.Employer = strings.TrimSpace(sanitizer.SanitizeString(e.Employer))
	e.JobTitle = strings.TrimSpace(sanitizer.SanitizeString(e.JobTitle))
	e.Location = strings.TrimSpace(sanitizer.SanitizeString(e.Location))
	e.StartDate = strings.TrimSpace(e.StartDate)
	e.EndDate = strings.TrimSpace(e.EndDate)
	e.Description = strings.TrimSpace(sanitizer.SanitizeString(e.Description))

	filteredAchievements := make([]string, 0, len(e.Achievements))
	for _, achievement := range e.Achievements {
		cleaned := strings.TrimSpace(sanitizer.SanitizeString(achievement))
		if cleaned != "" {
			filteredAchievements = append(filteredAchievements, cleaned)
		}
	}
	e.Achievements = filteredAchievements
}

func (e *Experience) ToJSON() ([]byte, error) {
	return MarshalJSON(e)
}

func (e *Experience) FromJSON(data []byte) error {
	return UnmarshalJSON(data, e)
}
