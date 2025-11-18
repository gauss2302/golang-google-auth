package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
	"googleAuth/internal/domain/dto"
	"googleAuth/internal/service"
	"net/http"
)

type SkillHandler struct {
	skillService service.SkillService
}

func NewSkillHandler(skillService service.SkillService) *SkillHandler {
	return &SkillHandler{
		skillService: skillService,
	}
}

// CreateSkill обрабатывает POST /api/v1/skills
// Создает новый навык для аутентифицированного пользователя
func (h *SkillHandler) CreateSkill(c *gin.Context) {
	// Получаем ID пользователя из JWT токена (устанавливается AuthMiddleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Парсим и валидируем тело запроса
	var req dto.SkillCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Создаем навык через сервисный слой
	skill, err := h.skillService.CreateSkill(c.Request.Context(), userID.(uuid.UUID), &req)
	if err != nil {
		if validationErrs, ok := err.(domain.ValidationErrors); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": validationErrs,
			})
			return
		}
		// Проверяем, является ли это ошибкой валидации из вашей системы
		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		// Общая ошибка сервера
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create skill",
		})
		return
	}

	// Возвращаем созданный навык со статусом 201
	c.JSON(http.StatusCreated, gin.H{
		"skill": skill,
	})
}

// GetUserSkills обрабатывает GET /api/v1/skills
// Получает все навыки пользователя с опциональной фильтрацией по категории
func (h *SkillHandler) GetUserSkills(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Проверяем параметр фильтрации по категории
	category := c.Query("category")

	var skills []*domain.Skill
	var err error

	if category != "" {
		// Получаем навыки по категории
		skills, err = h.skillService.GetUserSkillsByCategory(c.Request.Context(), userID.(uuid.UUID), category)
	} else {
		// Получаем все навыки пользователя
		skills, err = h.skillService.GetUserSkills(c.Request.Context(), userID.(uuid.UUID))
	}

	if err != nil {
		if validationErrs, ok := err.(domain.ValidationErrors); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"details": validationErrs,
			})
			return
		}
		// Проверяем ошибку валидации категории
		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve skills",
		})
		return
	}

	// Возвращаем навыки с метаданными
	c.JSON(http.StatusOK, gin.H{
		"skills": skills,
		"total":  len(skills),
		"filter": gin.H{
			"category": category,
		},
	})
}

// GetSkill обрабатывает GET /api/v1/skills/:id
// Получает конкретный навык по ID с проверкой прав доступа
func (h *SkillHandler) GetSkill(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Парсим ID навыка из URL параметра
	skillIDStr := c.Param("id")
	skillID, err := uuid.Parse(skillIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid skill ID format",
		})
		return
	}

	// Получаем навык через сервис (он проверит права доступа)
	skill, err := h.skillService.GetSkillByID(c.Request.Context(), skillID, userID.(uuid.UUID))
	if err != nil {
		// Обрабатываем различные типы ошибок
		switch err.Error() {
		case "skill not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Skill not found"})
		case "unauthorized: skill does not belong to the specified user":
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve skill"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"skill": skill,
	})
}

// UpdateSkill обрабатывает PUT /api/v1/skills/:id
// Обновляет существующий навык с проверкой прав доступа
func (h *SkillHandler) UpdateSkill(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Парсим ID навыка из URL
	skillIDStr := c.Param("id")
	skillID, err := uuid.Parse(skillIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid skill ID format",
		})
		return
	}

	// Парсим тело запроса
	var req dto.SkillUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Обновляем навык через сервис
	skill, err := h.skillService.UpdateSkill(c.Request.Context(), skillID, userID.(uuid.UUID), &req)
	if err != nil {
		if validationErrs, ok := err.(domain.ValidationErrors); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"details": validationErrs,
			})
			return
		}
		// Проверяем тип ошибки
		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Validation failed",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		// Проверяем другие специфичные ошибки
		switch err.Error() {
		case "skill not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Skill not found"})
		case "unauthorized: skill does not belong to the specified user":
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update skill"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"skill": skill,
	})
}

// DeleteSkill обрабатывает DELETE /api/v1/skills/:id
// Удаляет навык с проверкой прав доступа
func (h *SkillHandler) DeleteSkill(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Парсим ID навыка
	skillIDStr := c.Param("id")
	skillID, err := uuid.Parse(skillIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid skill ID format",
		})
		return
	}

	// Удаляем навык через сервис
	err = h.skillService.DeleteSkill(c.Request.Context(), skillID, userID.(uuid.UUID))
	if err != nil {
		switch err.Error() {
		case "skill not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "Skill not found"})
		case "unauthorized: skill does not belong to the specified user":
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete skill"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Skill deleted successfully",
	})
}

// GetSkillCategories обрабатывает GET /api/v1/skills/categories
// Возвращает все валидные категории навыков для UI компонентов
func (h *SkillHandler) GetSkillCategories(c *gin.Context) {
	categories := h.skillService.GetSkillCategories()

	c.JSON(http.StatusOK, gin.H{
		"categories": categories,
		"total":      len(categories),
	})
}

// CreateSkillsBatch обрабатывает POST /api/v1/skills/batch
// Создает несколько навыков за один запрос для повышения эффективности
func (h *SkillHandler) CreateSkillsBatch(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Парсим батч-запрос
	var req struct {
		Skills []*dto.SkillCreateRequest `json:"skills" binding:"required,min=1,max=50"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Дополнительная проверка размера батча
	if len(req.Skills) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Batch size cannot exceed 50 skills",
		})
		return
	}

	// Создаем навыки батчем
	skills, err := h.skillService.CreateSkillsBatch(c.Request.Context(), userID.(uuid.UUID), req.Skills)
	if err != nil {
		// Проверяем ошибки валидации
		if validationErr, ok := err.(*domain.ValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Batch validation failed",
				"field":   validationErr.Field,
				"message": validationErr.Message,
				"type":    validationErr.Type,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create skills batch",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"skills":  skills,
		"total":   len(skills),
		"message": "Skills created successfully",
	})
}

// DeleteAllUserSkills обрабатывает DELETE /api/v1/skills
// Удаляет ВСЕ навыки пользователя (с обязательным подтверждением)
func (h *SkillHandler) DeleteAllUserSkills(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Требуем явного подтверждения для безопасности
	confirmation := c.Query("confirm")
	if confirmation != "true" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "This action requires confirmation",
			"message": "Add '?confirm=true' to proceed with deleting all skills",
		})
		return
	}

	err := h.skillService.DeleteAllUserSkills(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete all skills",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "All skills deleted successfully",
	})
}
