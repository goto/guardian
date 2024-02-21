package postgres

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/internal/store/postgres/model"
	"gorm.io/gorm"
)

type commentRepository struct {
	db *gorm.DB
}

func NewCommentRepository(db *gorm.DB) *commentRepository {
	return &commentRepository{db}
}

func (r *commentRepository) Create(ctx context.Context, c *domain.Comment) error {
	m := &model.Comment{}
	if err := m.FromDomain(c); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(m).Error; err != nil {
			return err
		}

		newComment := m.ToDomain()
		*c = *newComment

		return nil
	})
}

func (r *commentRepository) List(ctx context.Context, filter domain.ListCommentsFilter) ([]*domain.Comment, error) {
	db := r.db.WithContext(ctx)
	if filter.AppealID != "" {
		db = db.Where("appeal_id = ?", filter.AppealID)
	}
	if filter.OrderBy != nil {
		for _, o := range filter.OrderBy {
			db = addOrderBy(db, o)
		}
	}
	var models []*model.Comment
	if err := db.Find(&models).Error; err != nil {
		return nil, err
	}

	comments := []*domain.Comment{}
	for _, m := range models {
		comments = append(comments, m.ToDomain())
	}
	return comments, nil
}
