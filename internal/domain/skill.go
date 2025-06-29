package domain

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"time"
)

// Константы категорий навыков
const (
	SkillCategoryLanguage  = "language"
	SkillCategoryFramework = "framework"
	SkillCategoryTool      = "tool"
	SkillCategoryDatabase  = "database"
	SkillCategoryOther     = "other"
)

// ValidSkillCategories - мапа для быстрой проверки валидности категории
var ValidSkillCategories = map[string]bool{
	SkillCategoryLanguage:  true,
	SkillCategoryFramework: true,
	SkillCategoryTool:      true,
	SkillCategoryDatabase:  true,
	SkillCategoryOther:     true,
}

// Skill представляет навык пользователя с уровнем владения
type Skill struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	Name        string    `json:"name" db:"name"`
	Category    string    `json:"category" db:"category"`
	Proficiency int       `json:"proficiency,omitempty" db:"proficiency"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Validate выполняет валидацию навыка, используя существующую ValidationError из вашего проекта
func (s *Skill) Validate() error {
	// Проверяем обязательные поля
	if strings.TrimSpace(s.Name) == "" {
		return NewValidationError("name", "Skill name is required", ErrInvalidField)
	}

	// Проверяем длину имени навыка
	if len(strings.TrimSpace(s.Name)) > 100 {
		return NewValidationError("name", "Skill name must not exceed 100 characters", ErrInvalidField)
	}

	// Проверяем категорию, если она указана (используем нашу специфичную логику)
	if s.Category != "" {
		if !ValidSkillCategories[s.Category] {
			return NewValidationError("category", fmt.Sprintf("Invalid category, must be one of: %s", strings.Join(getSkillCategoryKeys(), ", ")), ErrInvalidField)
		}
	}

	// Проверяем уровень владения, если он указан
	if s.Proficiency != 0 {
		if s.Proficiency < 1 || s.Proficiency > 5 {
			return NewValidationError("proficiency", "Proficiency must be between 1 and 5", ErrInvalidField)
		}
	}

	// Проверяем, что UserID не пустой
	if s.UserID == uuid.Nil {
		return NewValidationError("user_id", "User ID is required", ErrInvalidField)
	}

	return nil
}

// Вспомогательные функции

// GetSkillCategoryKeys возвращает все валидные категории навыков
func getSkillCategoryKeys() []string {
	keys := make([]string, 0, len(ValidSkillCategories))
	for k := range ValidSkillCategories {
		keys = append(keys, k)
	}
	return keys
}

func GetSkillCategoryKeys() []string {
	keys := make([]string, 0, len(ValidSkillCategories))
	for k := range ValidSkillCategories {
		keys = append(keys, k)
	}
	return keys
}

// BeforeSave подготавливает данные перед сохранением
func (s *Skill) BeforeSave() {
	// Очищаем строковые поля от лишних пробелов
	s.Name = strings.TrimSpace(s.Name)
	s.Category = strings.TrimSpace(s.Category)

	// Устанавливаем категорию по умолчанию, если не указана
	if s.Category == "" {
		s.Category = SkillCategoryOther
	}

	// Устанавливаем временные метки
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	// Генерируем ID для новых навыков
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
}

// ToJSON конвертирует навык в JSON
func (s *Skill) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// FromJSON парсит навык из JSON
func (s *Skill) FromJSON(data []byte) error {
	return json.Unmarshal(data, s)
}

// NewSkill создает новый навык с валидацией
func NewSkill(userID uuid.UUID, name, category string, proficiency int) (*Skill, error) {
	skill := &Skill{
		UserID:      userID,
		Name:        name,
		Category:    category,
		Proficiency: proficiency,
	}

	// Подготавливаем данные
	skill.BeforeSave()

	// Валидируем
	if err := skill.Validate(); err != nil {
		return nil, err
	}

	return skill, nil
}

// IsValidSkillCategory проверяет, является ли категория валидной
func IsValidSkillCategory(category string) bool {
	return ValidSkillCategories[category]
}
