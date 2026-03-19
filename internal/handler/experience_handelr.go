package handler

import (
	"net/http"

	"googleAuth/internal/domain"
	"googleAuth/internal/domain/dto"
	"googleAuth/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ExperienceHandler struct {
	experienceService service.ExperienceService
}

func NewExperienceHandler(experienceService service.ExperienceService) *ExperienceHandler {
	return &ExperienceHandler{
		experienceService: experienceService,
	}
}

// AddExperience handles POST /api/v1/experiences
// Creates a new experience entry for a resume
func (h *ExperienceHandler) AddExperience(c *gin.Context) {
	// Parse resume ID from request body or query parameter
	var req struct {
		ResumeID   string                      `json:"resume_id" binding:"required"`
		Experience dto.ExperienceCreateRequest `json:"experience" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	resumeID, err := uuid.Parse(req.ResumeID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid resume ID format",
		})
		return
	}

	// Create experience through service layer
	experience, err := h.experienceService.AddExperience(c.Request.Context(), resumeID, &req.Experience)
	if err != nil {
		if validationErrs, ok := err.(domain.ValidationErrors); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": validationErrs,
			})
			return
		}

		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		// Check for specific error messages
		switch err.Error() {
		case "resume ID cannot be nil":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Resume ID is required"})
		case "validation failed":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid experience data"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create experience",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"experience": experience,
	})
}

// GetExperience handles GET /api/v1/experiences/:id
// Retrieves a single experience entry by ID
func (h *ExperienceHandler) GetExperience(c *gin.Context) {
	experienceIDStr := c.Param("id")
	experienceID, err := uuid.Parse(experienceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid experience ID format",
		})
		return
	}

	experience, err := h.experienceService.GetExperience(c.Request.Context(), experienceID)
	if err != nil {
		switch err.Error() {
		case "invalid experience ID":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid experience ID"})
		case "experience not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Experience not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve experience",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"experience": experience,
	})
}

// GetExperiencesByResume handles GET /api/v1/experiences/resume/:resumeId
// Retrieves all experience entries for a resume
func (h *ExperienceHandler) GetExperiencesByResume(c *gin.Context) {
	resumeID := c.Param("resumeId")
	if resumeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Resume ID is required",
		})
		return
	}

	experiences, err := h.experienceService.GetExperiencesByResume(c.Request.Context(), resumeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve experiences",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"experiences": experiences,
		"total":       len(experiences),
	})
}

// UpdateExperience handles PUT /api/v1/experiences/:id
// Updates an existing experience entry
func (h *ExperienceHandler) UpdateExperience(c *gin.Context) {
	experienceIDStr := c.Param("id")
	experienceID, err := uuid.Parse(experienceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid experience ID format",
		})
		return
	}

	var req dto.ExperienceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	experience, err := h.experienceService.UpdateExperience(c.Request.Context(), experienceID, &req)
	if err != nil {
		if validationErrs, ok := err.(domain.ValidationErrors); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": validationErrs,
			})
			return
		}

		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		switch err.Error() {
		case "experience ID cannot be nil":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Experience ID is required"})
		case "experience not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Experience not found"})
		case "validation failed":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid experience data"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update experience",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"experience": experience,
	})
}

// DeleteExperience handles DELETE /api/v1/experiences/:id
// Deletes an experience entry by ID
func (h *ExperienceHandler) DeleteExperience(c *gin.Context) {
	experienceIDStr := c.Param("id")
	experienceID, err := uuid.Parse(experienceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid experience ID format",
		})
		return
	}

	err = h.experienceService.DeleteExperience(c.Request.Context(), experienceID)
	if err != nil {
		switch err.Error() {
		case "invalid experience ID":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid experience ID"})
		case "experience not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Experience not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete experience",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Experience deleted successfully",
	})
}

