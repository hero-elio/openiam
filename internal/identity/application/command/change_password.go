package command

type ChangePassword struct {
	UserID      string
	OldPassword string
	NewPassword string
}
