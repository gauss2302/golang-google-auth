package domain

import (
	"strings"
)

type Experience struct {
	Employer     string   `json:"employer"`
	JobTitle     string   `json:"title"`
	Location     string   `json:"location"`
	StartDate    string   `json:"start_date"` // Format: YYYY-MM-DD
	EndDate      string   `json:"end_date"`   // Format: YYYY-MM-DD or "Present"
	Description  string   `json:"description"`
	Achievements []string `json:"achievements,omitempty"`
}

func (e *Experience) Validate() error {
	vb := NewValidationBuilder[Experience]()

	vb.Field("employer", e.Employer).Required().String().NotEmpty().MaxLength(200).SecureSanitize()
	vb.Field("title", e.JobTitle).Required().String().NotEmpty().MaxLength(200).SecureSanitize()
	vb.Field("start_date", e.StartDate).Required().Date().ISO8601()

	if e.Location != "" {
		vb.Field("location", e.Location).String().MaxLength(200).SecureSanitize()
	}

	if e.EndDate != "" {
		if e.EndDate != "Present" {
			vb.Field("end_date", e.EndDate).Date().ISO8601().After(e.EndDate)
		}
	}

	if e.Description != "" {
		vb.Field("description", e.Description).String().MaxLength(2000).SecureSanitize()
	}

	if len(e.Achievements) > 0 {
		vb.Field("achievements", e.Achievements).StringSlice().
			MaxLength(20).
			EachMaxLength(500).
			EachSecureSanitize()
	}

	return vb.Build()
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
