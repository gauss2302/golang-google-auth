package domain

import (
	"encoding/json"
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
	UserID      uuid.UUID `json:"user_id" db:"user_id" validate:"required"`
	Name        string    `json:"name" db:"name" validate:"required,min=1,max=100"`
	Category    string    `json:"category" db:"category" validate:"omitempty,oneof=language framework tool database other"`
	Proficiency int       `json:"proficiency,omitempty" db:"proficiency" validate:"omitempty,min=1,max=5"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Validate выполняет валидацию навыка через общий валидатор пакета.
func (s *Skill) Validate() error {
	return formatValidationErrors("skill", domainValidator.Struct(s))
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
