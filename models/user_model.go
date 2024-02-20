package models

type User struct {
	// Id	primitive.ObjectID	`json:"id,omitempty"`
	Name     string `json:"name,omitempty" validate:"required"`
	Location string `json:"location,omitempty" validate:"required"`
	Title    string `json:"title,omitempty" validate:"required"`
}

type UserPW struct {
	Name     string `json:"name,omitempty" validate:"required"`
	Password string `json:"password,omitempty" validate:"required"`
	Email    string `json:"email,omitempty" validate:"required"`
}

type UserLogin struct {
	Email    string `json:"email,omitempty" validate:"required"`
	Password string `json:"password,omitempty" validate:"required"`
}
