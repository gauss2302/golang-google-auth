package dto

import (
	"github.com/google/uuid"
	"googleAuth/internal/domain"
)

// SkillCreateRequest представляет запрос на создание нового навыка
type SkillCreateRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Category    string `json:"category" binding:"omitempty,oneof=language framework tool database other"`
	Proficiency int    `json:"proficiency" binding:"omitempty,min=1,max=5"`
}

// SkillUpdateRequest представляет запрос на обновление существующего навыка
// Все поля опциональны для поддержки частичных обновлений
type SkillUpdateRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Category    *string `json:"category,omitempty" binding:"omitempty,oneof=language framework tool database other"`
	Proficiency *int    `json:"proficiency,omitempty" binding:"omitempty,min=1,max=5"`
}

// ToSkill конвертирует SkillCreateRequest в domain модель
func (req *SkillCreateRequest) ToSkill(userID uuid.UUID) *domain.Skill {
	return &domain.Skill{
		UserID:      userID,
		Name:        req.Name,
		Category:    req.Category,
		Proficiency: req.Proficiency,
	}
}

// ApplyTo применяет обновления из SkillUpdateRequest к существующей domain модели
// Обновляет только те поля, которые были предоставлены в запросе (не nil)
func (req *SkillUpdateRequest) ApplyTo(skill *domain.Skill) {
	if req.Name != nil {
		skill.Name = *req.Name
	}
	if req.Category != nil {
		skill.Category = *req.Category
	}
	if req.Proficiency != nil {
		skill.Proficiency = *req.Proficiency
	}
}

// SkillResponse представляет ответ API для навыка
// Можно использовать для кастомизации выходных данных без изменения domain модели
type SkillResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Proficiency int       `json:"proficiency,omitempty"`
	CreatedAt   string    `json:"created_at"`
	UpdatedAt   string    `json:"updated_at"`
}

// FromDomain конвертирует domain.Skill в SkillResponse
func (resp *SkillResponse) FromDomain(skill *domain.Skill) *SkillResponse {
	return &SkillResponse{
		ID:          skill.ID,
		Name:        skill.Name,
		Category:    skill.Category,
		Proficiency: skill.Proficiency,
		CreatedAt:   skill.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   skill.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// SkillsListResponse представляет ответ для списка навыков
type SkillsListResponse struct {
	Skills []*SkillResponse `json:"skills"`
	Total  int              `json:"total"`
	Filter FilterInfo       `json:"filter,omitempty"`
}

// FilterInfo содержит информацию о примененных фильтрах
type FilterInfo struct {
	Category string `json:"category,omitempty"`
}

// BatchCreateRequest представляет запрос на создание нескольких навыков
type BatchCreateRequest struct {
	Skills []*SkillCreateRequest `json:"skills" binding:"required,min=1,max=50"`
}

// CategoriesResponse представляет ответ со списком категорий
type CategoriesResponse struct {
	Categories []string `json:"categories"`
	Total      int      `json:"total"`
}
