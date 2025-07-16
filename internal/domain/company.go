package domain

import (
	"github.com/google/uuid"
	"time"
)

type CompanySize string

const (
	CompanySizeStartup    CompanySize = "startup"    // 1-10 employees
	CompanySizeSmall      CompanySize = "small"      // 11-50 employees
	CompanySizeMedium     CompanySize = "medium"     // 51-200 employees
	CompanySizeLarge      CompanySize = "large"      // 201-1000 employees
	CompanySizeEnterprise CompanySize = "enterprise" // 1000+ employees
)

// CompanyType represents the type/stage of company
type CompanyType string

const (
	CompanyTypeStartup   CompanyType = "startup"
	CompanyTypeScaleup   CompanyType = "scaleup"
	CompanyTypePublic    CompanyType = "public"
	CompanyTypePrivate   CompanyType = "private"
	CompanyTypeNonProfit CompanyType = "non_profit"
	CompanyTypeAgency    CompanyType = "agency"
)

// Address represents a physical address
type Address struct {
	Street     string   `json:"street" db:"street"`
	City       string   `json:"city" db:"city"`
	State      string   `json:"state" db:"state"`
	PostalCode string   `json:"postal_code" db:"postal_code"`
	Country    string   `json:"country" db:"country"`
	Latitude   *float64 `json:"latitude,omitempty" db:"latitude"`
	Longitude  *float64 `json:"longitude,omitempty" db:"longitude"`
}

// SocialLinks represents company's social media presence
type SocialLinks struct {
	LinkedIn  *string `json:"linkedin,omitempty" db:"linkedin"`
	Twitter   *string `json:"twitter,omitempty" db:"twitter"`
	Facebook  *string `json:"facebook,omitempty" db:"facebook"`
	Instagram *string `json:"instagram,omitempty" db:"instagram"`
	YouTube   *string `json:"youtube,omitempty" db:"youtube"`
	GitHub    *string `json:"github,omitempty" db:"github"`
}

// CompanyBenefits represents benefits offered by the company
type CompanyBenefits struct {
	HealthInsurance  bool `json:"health_insurance" db:"health_insurance"`
	DentalInsurance  bool `json:"dental_insurance" db:"dental_insurance"`
	VisionInsurance  bool `json:"vision_insurance" db:"vision_insurance"`
	RetirementPlan   bool `json:"retirement_plan" db:"retirement_plan"`
	PaidTimeOff      bool `json:"paid_time_off" db:"paid_time_off"`
	FlexibleSchedule bool `json:"flexible_schedule" db:"flexible_schedule"`
	RemoteWork       bool `json:"remote_work" db:"remote_work"`
	ProfessionalDev  bool `json:"professional_development" db:"professional_development"`
	StockOptions     bool `json:"stock_options" db:"stock_options"`
	PerformanceBonus bool `json:"performance_bonus" db:"performance_bonus"`
}

// Company represents a company entity in the career platform
type Company struct {
	// Primary identifiers
	ID   uuid.UUID `json:"id" db:"id" validate:"required"`
	Slug string    `json:"slug" db:"slug" validate:"required,min=2,max=100"`

	// Basic information
	Name        string  `json:"name" db:"name" validate:"required,min=1,max=255"`
	LegalName   *string `json:"legal_name,omitempty" db:"legal_name"`
	Description string  `json:"description" db:"description" validate:"required,min=10,max=2000"`
	Tagline     *string `json:"tagline,omitempty" db:"tagline" validate:"omitempty,max=255"`

	// Classification
	Industry    string      `json:"industry" db:"industry" validate:"required"`
	Size        CompanySize `json:"size" db:"size" validate:"required"`
	Type        CompanyType `json:"type" db:"type" validate:"required"`
	FoundedYear *int        `json:"founded_year,omitempty" db:"founded_year" validate:"omitempty,min=1800,max=2030"`

	// Contact and location
	Website      string   `json:"website" db:"website" validate:"required,url"`
	Email        *string  `json:"email,omitempty" db:"email" validate:"omitempty,email"`
	Phone        *string  `json:"phone,omitempty" db:"phone"`
	Address      *Address `json:"address,omitempty"`
	Headquarters string   `json:"headquarters" db:"headquarters" validate:"required"`

	// Media and branding
	LogoURL  *string `json:"logo_url,omitempty" db:"logo_url" validate:"omitempty,url"`
	CoverURL *string `json:"cover_url,omitempty" db:"cover_url" validate:"omitempty,url"`
	VideoURL *string `json:"video_url,omitempty" db:"video_url" validate:"omitempty,url"`

	// Social presence
	SocialLinks *SocialLinks `json:"social_links,omitempty"`

	// Company culture and benefits
	Culture      *string          `json:"culture,omitempty" db:"culture"`
	Values       []string         `json:"values,omitempty" db:"values"`
	Benefits     *CompanyBenefits `json:"benefits,omitempty"`
	Technologies []string         `json:"technologies,omitempty" db:"technologies"`

	// Business metrics
	EmployeeCount   *int       `json:"employee_count,omitempty" db:"employee_count" validate:"omitempty,min=1"`
	AnnualRevenue   *string    `json:"annual_revenue,omitempty" db:"annual_revenue"`
	FundingRaised   *string    `json:"funding_raised,omitempty" db:"funding_raised"`
	StockSymbol     *string    `json:"stock_symbol,omitempty" db:"stock_symbol"`
	ParentCompanyID *uuid.UUID `json:"parent_company_id,omitempty" db:"parent_company_id"`

	// Platform-specific fields
	IsVerified      bool     `json:"is_verified" db:"is_verified" default:"false"`
	IsActive        bool     `json:"is_active" db:"is_active" default:"true"`
	IsFeatured      bool     `json:"is_featured" db:"is_featured" default:"false"`
	IsHiring        bool     `json:"is_hiring" db:"is_hiring" default:"false"`
	JobPostingCount int      `json:"job_posting_count" db:"job_posting_count" default:"0"`
	AverageRating   *float64 `json:"average_rating,omitempty" db:"average_rating" validate:"omitempty,min=0,max=5"`
	ReviewCount     int      `json:"review_count" db:"review_count" default:"0"`

	// SEO and metadata
	MetaTitle       *string  `json:"meta_title,omitempty" db:"meta_title"`
	MetaDescription *string  `json:"meta_description,omitempty" db:"meta_description"`
	Keywords        []string `json:"keywords,omitempty" db:"keywords"`

	// Audit fields
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedBy uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

func (c *Company) CompanyValidate() {
	vb := NewValidationBuilder[Company]()

	vb.Field("name", c.Name).Required().String().NotEmpty().MaxLength(40).SecureSanitize()
}
