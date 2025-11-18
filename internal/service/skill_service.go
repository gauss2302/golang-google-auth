package service

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
	"googleAuth/internal/domain/dto"
	"strings"
)

type SkillService interface {
	CreateSkill(ctx context.Context, userID uuid.UUID, req *dto.SkillCreateRequest) (*domain.Skill, error)
	GetUserSkills(ctx context.Context, userID uuid.UUID) ([]*domain.Skill, error)
	GetUserSkillsByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*domain.Skill, error)
	GetSkillByID(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) (*domain.Skill, error) // Добавлен userID для проверки прав
	UpdateSkill(ctx context.Context, skillID uuid.UUID, userID uuid.UUID, req *dto.SkillUpdateRequest) (*domain.Skill, error)
	DeleteSkill(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) error
	DeleteAllUserSkills(ctx context.Context, userID uuid.UUID) error

	// Batch операции
	CreateSkillsBatch(ctx context.Context, userID uuid.UUID, requests []*dto.SkillCreateRequest) ([]*domain.Skill, error)

	// Вспомогательные методы
	GetSkillCategories() []string
	ValidateSkillOwnership(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) error
}

type skillService struct {
	skillRepo domain.SkillRepository
}

func (s *skillService) CreateSkillsBatch(ctx context.Context, userID uuid.UUID, requests []*dto.SkillCreateRequest) ([]*domain.Skill, error) {
	//TODO implement me
	panic("implement me")
}

func (s *skillService) DeleteAllUserSkills(ctx context.Context, userID uuid.UUID) error {
	//TODO implement me
	panic("implement me")
}

func NewSkillService(skillRepo domain.SkillRepository) SkillService {
	return &skillService{skillRepo: skillRepo}
}

func (s *skillService) CreateSkill(ctx context.Context, userID uuid.UUID, req *dto.SkillCreateRequest) (*domain.Skill, error) {
	skill := req.ToSkill(userID)

	skill.BeforeSave()

	if err := skill.Validate(); err != nil {
		return nil, err
	}

	existingSkills, err := s.skillRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for duplicate skills: %w", err)
	}

	for _, existing := range existingSkills {
		if strings.EqualFold(existing.Name, skill.Name) {
			return nil, domain.NewValidationError("name",
				"You already have this skill. Consider updating the existing one instead.",
				domain.ErrInvalidField)
		}
	}

	if err := s.skillRepo.Create(ctx, skill); err != nil {
		return nil, fmt.Errorf("failed to create skill: %w", err)
	}
	return skill, err
}

func (s *skillService) GetUserSkills(ctx context.Context, userID uuid.UUID) ([]*domain.Skill, error) {
	skills, err := s.skillRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user skills: %w", err)
	}

	if skills == nil {
		skills = []*domain.Skill{}
	}

	return skills, nil
}

func (s *skillService) GetUserSkillsByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*domain.Skill, error) {
	filter := struct {
		Category string `validate:"required,oneof=language framework tool database other"`
	}{Category: category}

	if err := domain.ValidateStruct(filter); err != nil {
		return nil, err
	}

	skills, err := s.skillRepo.GetByUserIDAndCategory(ctx, userID, category)
	if err != nil {
		return nil, fmt.Errorf("failed to get user skills by category: %w", err)
	}

	if skills == nil {
		skills = []*domain.Skill{}
	}

	return skills, nil

}

func (s *skillService) GetSkillByID(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) (*domain.Skill, error) {
	// Сначала проверяем права доступа
	if err := s.ValidateSkillOwnership(ctx, skillID, userID); err != nil {
		return nil, err
	}

	// Получаем навык
	skill, err := s.skillRepo.GetByID(ctx, skillID)
	if err != nil {
		return nil, fmt.Errorf("failed to get skill: %w", err)
	}

	if skill == nil {
		return nil, fmt.Errorf("skill not found")
	}

	return skill, nil
}

func (s *skillService) UpdateSkill(ctx context.Context, skillID uuid.UUID, userID uuid.UUID, req *dto.SkillUpdateRequest) (*domain.Skill, error) {
	// Получаем существующий навык с проверкой прав
	skill, err := s.GetSkillByID(ctx, skillID, userID)
	if err != nil {
		return nil, err
	}

	// Применяем обновления
	req.ApplyTo(skill)

	// Подготавливаем и валидируем
	skill.BeforeSave()
	if err := skill.Validate(); err != nil {
		return nil, err
	}

	// Проверяем конфликты имен, если имя изменилось
	if req.Name != nil {
		existingSkills, err := s.skillRepo.GetByUserID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to check for duplicate skills: %w", err)
		}

		for _, existing := range existingSkills {
			if existing.ID == skillID {
				continue // Пропускаем текущий навык
			}
			if strings.EqualFold(existing.Name, skill.Name) {
				return nil, domain.NewValidationError("name",
					"You already have a skill with this name.",
					domain.ErrInvalidField)
			}
		}
	}

	// Сохраняем обновления
	if err := s.skillRepo.Update(ctx, skill); err != nil {
		return nil, fmt.Errorf("failed to update skill: %w", err)
	}

	return skill, nil
}

func (s *skillService) DeleteSkill(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) error {
	// Проверяем права доступа
	if err := s.ValidateSkillOwnership(ctx, skillID, userID); err != nil {
		return err
	}

	if err := s.skillRepo.Delete(ctx, skillID); err != nil {
		return fmt.Errorf("failed to delete skill: %w", err)
	}

	return nil
}

func (s *skillService) GetSkillCategories() []string {
	return domain.GetSkillCategoryKeys()
}

func (s *skillService) ValidateSkillOwnership(ctx context.Context, skillID uuid.UUID, userID uuid.UUID) error {
	skill, err := s.skillRepo.GetByID(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if skill == nil {
		return fmt.Errorf("skill not found")
	}

	if skill.UserID != userID {
		return fmt.Errorf("unauthorized: skill does not belong to the specified user")
	}

	return nil
}
