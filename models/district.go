package models

type District struct {
	BaseModel

	CityID uint   `gorm:"index;not null" json:"city_id"`
	Name   string `gorm:"type:varchar(100);not null;index" json:"name"`

	City *City `gorm:"foreignKey:CityID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"city,omitempty"`
}

func (District) TableName() string {
	return "districts"
}
