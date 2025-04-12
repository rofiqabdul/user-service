package error

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrPasswordIncorrect   = errors.New("password incorrect")
	ErrUsernameExists      = errors.New("username already exists")
	ErrEmailExists         = errors.New("email already exists")
	ErrPasswordDidNotMatch = errors.New("password did not match")
)

var UserErrors = []error{
	ErrUserNotFound,
	ErrPasswordIncorrect,
	ErrUsernameExists,
	ErrPasswordDidNotMatch,
}
