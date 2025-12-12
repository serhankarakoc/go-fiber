package models

import (
	"context"
	"time"

	"zatrano/packages/currentuser"

	"gorm.io/gorm"
)

type BaseModel struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	CreatedBy uint  `gorm:"column:created_by;index" json:"created_by"`
	UpdatedBy uint  `gorm:"column:updated_by;index" json:"updated_by"`
	DeletedBy *uint `gorm:"column:deleted_by;index" json:"deleted_by,omitempty"`
	IsActive  bool  `gorm:"default:true;index" json:"is_active"`
}

func getCurrentUserID(ctx context.Context) uint {
	cu := currentuser.FromContext(ctx)
	if cu.ID != 0 {
		return cu.ID
	}
	return 0
}

func RegisterBaseModelCallbacks(db *gorm.DB) {
	db.Callback().Create().Before("gorm:create").Register("base_model:before_create", func(tx *gorm.DB) {
		cuID := getCurrentUserID(tx.Statement.Context)
		if tx.Statement.Schema == nil {
			return
		}

		rv := tx.Statement.ReflectValue

		if f := tx.Statement.Schema.LookUpField("created_by"); f != nil {
			_ = f.Set(tx.Statement.Context, rv, cuID)
		}
		if f := tx.Statement.Schema.LookUpField("updated_by"); f != nil {
			_ = f.Set(tx.Statement.Context, rv, cuID)
		}
		if f := tx.Statement.Schema.LookUpField("is_active"); f != nil {
			if !rv.FieldByName("IsActive").Bool() {
				_ = f.Set(tx.Statement.Context, rv, true)
			}
		}
	})

	db.Callback().Update().Before("gorm:update").Register("base_model:before_update", func(tx *gorm.DB) {
		cuID := getCurrentUserID(tx.Statement.Context)
		if tx.Statement.Schema == nil {
			return
		}

		rv := tx.Statement.ReflectValue
		if f := tx.Statement.Schema.LookUpField("updated_by"); f != nil {
			_ = f.Set(tx.Statement.Context, rv, cuID)
		}
	})

	db.Callback().Delete().Before("gorm:delete").Register("base_model:before_delete", func(tx *gorm.DB) {
		cuID := getCurrentUserID(tx.Statement.Context)
		if tx.Statement.Schema == nil {
			return
		}

		rv := tx.Statement.ReflectValue
		if f := tx.Statement.Schema.LookUpField("deleted_by"); f != nil {
			_ = f.Set(tx.Statement.Context, rv, cuID)
		}
		if f := tx.Statement.Schema.LookUpField("updated_by"); f != nil {
			_ = f.Set(tx.Statement.Context, rv, cuID)
		}
	})
}
