package model

type Person struct {
	ID             int    `json:"id"`
	ProfilePicture string `json:"profile_picture"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	HashedPassword string `json:"hashed_password"`
	Phone          int    `json:"phone"`
	Gender         string `json:"gender"`
}
