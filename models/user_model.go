package models

type User struct {
	Name     string `json:"name,omitempty" validate:"required"`
	Password string `json:"password,omitempty" validate:"required"`
	Email    string `json:"email,omitempty" validate:"required"`
}

type UserLogin struct {
	Email    string `json:"email,omitempty" validate:"required"`
	Password string `json:"password,omitempty" validate:"required"`
}
