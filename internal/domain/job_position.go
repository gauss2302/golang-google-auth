package domain

import (
	"fmt"
	"github.com/google/uuid"
	"time"
)

type JobType string

const (
	JobTypeFullTime   JobType = "full_time"
	JobTypePartTime   JobType = "part_time"
	JobTypeContract   JobType = "contract"
	JobTypeFreelance  JobType = "freelance"
	JobTypeInternship JobType = "internship"
	JobTypeTemporary  JobType = "temporary"
)

type WorkArrangement string

const (
	WorkArrangementOnSite WorkArrangement = "on_site"
	WorkArrangementRemote WorkArrangement = "remote"
	WorkArrangementHybrid WorkArrangement = "hybrid"
)

type ExperienceLevel string

const (
	ExperienceLevelEntry     ExperienceLevel = "entry"     // 0-2 years
	ExperienceLevelJunior    ExperienceLevel = "junior"    // 2-4 years
	ExperienceLevelMid       ExperienceLevel = "mid"       // 4-7 years
	ExperienceLevelSenior    ExperienceLevel = "senior"    // 7-12 years
	ExperienceLevelLead      ExperienceLevel = "lead"      // 10+ years
	ExperienceLevelExecutive ExperienceLevel = "executive" // 15+ years
)

type JobStatus string

const (
	JobStatusDraft     JobStatus = "draft"
	JobStatusActive    JobStatus = "active"
	JobStatusPaused    JobStatus = "paused"
	JobStatusFilled    JobStatus = "filled"
	JobStatusCancelled JobStatus = "cancelled"
	JobStatusExpired   JobStatus = "expired"
)

type EducationLevel string

const (
	EducationLevelHighSchool EducationLevel = "high_school"
	EducationLevelAssociate  EducationLevel = "associate"
	EducationLevelBachelor   EducationLevel = "bachelor"
	EducationLevelMaster     EducationLevel = "master"
	EducationLevelDoctorate  EducationLevel = "doctorate"
	EducationLevelNone       EducationLevel = "none"
)

type Currency string

const (
	CurrencyUSD Currency = "USD"
	CurrencyEUR Currency = "EUR"
	CurrencyGBP Currency = "GBP"
	CurrencyCAD Currency = "CAD"
	CurrencyAUD Currency = "AUD"
)

type SalaryRange struct {
	MinAmount    *int64   `json:"min_amount,omitempty" db:"min_amount"`
	MaxAmount    *int64   `json:"max_amount,omitempty" db:"max_amount"`
	Currency     Currency `json:"currency" db:"currency" validate:"required"`
	Period       string   `json:"period" db:"period" validate:"required"` // "hourly", "monthly", "yearly"
	IsNegotiable bool     `json:"is_negotiable" db:"is_negotiable" default:"false"`
	ShowSalary   bool     `json:"show_salary" db:"show_salary" default:"true"`
}

type JobLocation struct {
	City       string   `json:"city" db:"city"`
	State      string   `json:"state" db:"state"`
	Country    string   `json:"country" db:"country" validate:"required"`
	PostalCode *string  `json:"postal_code,omitempty" db:"postal_code"`
	Timezone   *string  `json:"timezone,omitempty" db:"timezone"`
	IsRemote   bool     `json:"is_remote" db:"is_remote" default:"false"`
	Latitude   *float64 `json:"latitude,omitempty" db:"latitude"`
	Longitude  *float64 `json:"longitude,omitempty" db:"longitude"`
}

type ApplicationMethod struct {
	Type           string  `json:"type" db:"type" validate:"required"` // "internal", "external", "email"
	URL            *string `json:"url,omitempty" db:"url" validate:"omitempty,url"`
	Email          *string `json:"email,omitempty" db:"email" validate:"omitempty,email"`
	Instructions   *string `json:"instructions,omitempty" db:"instructions"`
	RequiresResume bool    `json:"requires_resume" db:"requires_resume" default:"true"`
	RequiresCover  bool    `json:"requires_cover_letter" db:"requires_cover_letter" default:"false"`
}

type JobRequirements struct {
	MinExperience     *int            `json:"min_experience_years,omitempty" db:"min_experience_years"`
	MaxExperience     *int            `json:"max_experience_years,omitempty" db:"max_experience_years"`
	EducationLevel    *EducationLevel `json:"education_level,omitempty" db:"education_level"`
	RequiredSkills    []string        `json:"required_skills,omitempty" db:"required_skills"`
	PreferredSkills   []string        `json:"preferred_skills,omitempty" db:"preferred_skills"`
	Languages         []string        `json:"languages,omitempty" db:"languages"`
	Certifications    []string        `json:"certifications,omitempty" db:"certifications"`
	Tools             []string        `json:"tools,omitempty" db:"tools"`
	SecurityClearance *string         `json:"security_clearance,omitempty" db:"security_clearance"`
	TravelRequired    *int            `json:"travel_percentage,omitempty" db:"travel_percentage"` // 0-100
}

type JobBenefits struct {
	HealthInsurance      bool     `json:"health_insurance" db:"health_insurance"`
	DentalInsurance      bool     `json:"dental_insurance" db:"dental_insurance"`
	VisionInsurance      bool     `json:"vision_insurance" db:"vision_insurance"`
	RetirementPlan       bool     `json:"retirement_plan" db:"retirement_plan"`
	PaidTimeOff          bool     `json:"paid_time_off" db:"paid_time_off"`
	FlexibleSchedule     bool     `json:"flexible_schedule" db:"flexible_schedule"`
	RemoteWork           bool     `json:"remote_work" db:"remote_work"`
	ProfessionalDev      bool     `json:"professional_development" db:"professional_development"`
	StockOptions         bool     `json:"stock_options" db:"stock_options"`
	PerformanceBonus     bool     `json:"performance_bonus" db:"performance_bonus"`
	SigningBonus         bool     `json:"signing_bonus" db:"signing_bonus"`
	RelocationAssistance bool     `json:"relocation_assistance" db:"relocation_assistance"`
	GymMembership        bool     `json:"gym_membership" db:"gym_membership"`
	MealAllowance        bool     `json:"meal_allowance" db:"meal_allowance"`
	TransportAllowance   bool     `json:"transport_allowance" db:"transport_allowance"`
	ChildcareSupport     bool     `json:"childcare_support" db:"childcare_support"`
	CustomBenefits       []string `json:"custom_benefits,omitempty" db:"custom_benefits"`
}

type JobPosition struct {
	// Primary identifiers
	ID   uuid.UUID `json:"id" db:"id" validate:"required"`
	Slug string    `json:"slug" db:"slug" validate:"required,min=2,max=150"`

	// Company relationship
	CompanyID uuid.UUID `json:"company_id" db:"company_id" validate:"required"`
	Company   *Company  `json:"company,omitempty"` // For eager loading

	// Basic information
	Title       string `json:"title" db:"title" validate:"required,min=2,max=255"`
	Description string `json:"description" db:"description" validate:"required,min=50"`
	Summary     string `json:"summary" db:"summary" validate:"required,min=20,max=500"`

	// Job classification
	JobType         JobType         `json:"job_type" db:"job_type" validate:"required"`
	WorkArrangement WorkArrangement `json:"work_arrangement" db:"work_arrangement" validate:"required"`
	ExperienceLevel ExperienceLevel `json:"experience_level" db:"experience_level" validate:"required"`
	Department      string          `json:"department" db:"department" validate:"required"`
	Category        string          `json:"category" db:"category" validate:"required"`
	Seniority       string          `json:"seniority" db:"seniority"`

	// Location and salary
	Location    *JobLocation `json:"location,omitempty"`
	SalaryRange *SalaryRange `json:"salary_range,omitempty"`

	// Requirements and qualifications
	Requirements *JobRequirements `json:"requirements,omitempty"`
	Benefits     *JobBenefits     `json:"benefits,omitempty"`

	// Application details
	ApplicationMethod   *ApplicationMethod `json:"application_method,omitempty"`
	ApplicationDeadline *time.Time         `json:"application_deadline,omitempty" db:"application_deadline"`

	// Job details
	StartDate      *time.Time `json:"start_date,omitempty" db:"start_date"`
	Duration       *string    `json:"duration,omitempty" db:"duration"` // For contracts/temp jobs
	PositionsOpen  int        `json:"positions_open" db:"positions_open" default:"1"`
	ReportsTo      *string    `json:"reports_to,omitempty" db:"reports_to"`
	TeamSize       *int       `json:"team_size,omitempty" db:"team_size"`
	WorkSchedule   *string    `json:"work_schedule,omitempty" db:"work_schedule"`
	IsUrgent       bool       `json:"is_urgent" db:"is_urgent" default:"false"`
	IsConfidential bool       `json:"is_confidential" db:"is_confidential" default:"false"`

	// Platform-specific fields
	Status           JobStatus `json:"status" db:"status" validate:"required" default:"draft"`
	IsFeatured       bool      `json:"is_featured" db:"is_featured" default:"false"`
	IsPromoted       bool      `json:"is_promoted" db:"is_promoted" default:"false"`
	ViewCount        int       `json:"view_count" db:"view_count" default:"0"`
	ApplicationCount int       `json:"application_count" db:"application_count" default:"0"`
	SaveCount        int       `json:"save_count" db:"save_count" default:"0"`
	ShareCount       int       `json:"share_count" db:"share_count" default:"0"`
	ExternalJobID    *string   `json:"external_job_id,omitempty" db:"external_job_id"`
	SourcePlatform   *string   `json:"source_platform,omitempty" db:"source_platform"`

	// SEO and discoverability
	Tags            []string `json:"tags,omitempty" db:"tags"`
	Keywords        []string `json:"keywords,omitempty" db:"keywords"`
	MetaTitle       *string  `json:"meta_title,omitempty" db:"meta_title"`
	MetaDescription *string  `json:"meta_description,omitempty" db:"meta_description"`

	// Dates and lifecycle
	PublishedAt *time.Time `json:"published_at,omitempty" db:"published_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	FilledAt    *time.Time `json:"filled_at,omitempty" db:"filled_at"`

	// Audit fields
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedBy uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

func (j *JobPosition) IsActive() bool {
	now := time.Now()
	return j.Status == JobStatusActive &&
		(j.ExpiresAt == nil || j.ExpiresAt.After(now)) &&
		(j.ApplicationDeadline == nil || j.ApplicationDeadline.After(now))
}

func (j *JobPosition) IsExpired() bool {
	now := time.Now()
	return (j.ExpiresAt != nil && j.ExpiresAt.Before(now)) ||
		(j.ApplicationDeadline != nil && j.ApplicationDeadline.Before(now))
}

func (j *JobPosition) GetSalaryString() string {
	if j.SalaryRange == nil || !j.SalaryRange.ShowSalary {
		return "Salary is hidden"
	}

	if j.SalaryRange.IsNegotiable {
		return "Negotiable"
	}

	if j.SalaryRange.MinAmount != nil && j.SalaryRange.MaxAmount != nil {
		return fmt.Sprintf("%s %d - %d per %s",
			j.SalaryRange.Currency,
			*j.SalaryRange.MinAmount,
			*j.SalaryRange.MaxAmount,
			j.SalaryRange.Period)
	}

	if j.SalaryRange.MinAmount != nil {
		return fmt.Sprintf("%s %d+ per %s",
			j.SalaryRange.Currency,
			*j.SalaryRange.MinAmount,
			j.SalaryRange.Period)
	}

	return "Competitive salary"
}

func (j *JobPosition) CanApply() bool {
	return j.IsActive()
}
