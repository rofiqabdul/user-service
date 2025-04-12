package services

import (
	"context"
	"strings"
	"time"
	"user-service/config"
	"user-service/constants"
	errConstant "user-service/constants/error"
	"user-service/domain/dto"
	"user-service/repositories"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/consul/agent/hcp/bootstrap/constants"
	"golang.org/x/crypto/bcrypt"
)

type UserServcie struct {
	repository repositories.IRepositoryRegistry
}

type Claims struct {
	User *dto.UserResponse
	jwt.RegisteredClaims
}

type IUserService interface {
	Login(context.Context, *dto.LoginRequest) (*dto.LoignResponse, error)
	Register(context.Context, *dto.RegisterRequest) (*dto.RegisterResponse, error)
	Update(context.Context, *dto.UpdateRequest) (*dto.UserResponse, error)
	GetUserLogin(context.Context) (*dto.UserResponse, error)
	GetUserByUUID(context.Context) (*dto.LoginRequest, error)
}

func NewUserService(repository repositories.IRepositoryRegistry) IUserService {
	return &UserServcie{repository: repository}
}

func (u *UserServcie) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoignResponse, error) {
	user, err := u.repository.GetUser().FindByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, err
	}

	expirationTime := time.Now().Add(time.Duration(config.Conifg.JwtExpirationTime) * time.Minute).Unix()
	data := &dto.UserResponse{
		UUID:        user.UUID,
		Name:        user.Name,
		Username:    user.Username,
		PhoneNumber: user.PhoneNumber,
		Email:       user.Email,
		Role:        strings.ToLower(user.Role.Code),
	}

	claims := &Claims{
		User: data,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expirationTime, 0)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Conifg.JwtSecretKey))
	if err != nil {
		return nil, err
	}

	respone := &dto.LoignResponse{
		User:  *data,
		Token: tokenString,
	}

	return respone, nil
}

func (u *UserServcie) isUsernameExist(ctx context.Context, username string) bool {
	user, err := u.repository.GetUser().FindByUsername(ctx, username)
	if err != nil {
		return false
	}

	if user != nil {
		return true
	}

	return false
}

func (u *UserServcie) isEmailExist(ctx context.Context, email string) bool {
	user, err := u.repository.GetUser().FindByEmail(ctx, email)
	if err != nil {
		return false
	}

	if user != nil {
		return true
	}

	return false
}

func (u *UserServcie) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	if u.isUsernameExist(ctx, req.Username) {
		return nil, errConstant.ErrUsernameExists
	}

	if u.isEmailExist(ctx, req.Emial) {
		return nil, errConstant.ErrEmailExists
	}

	if req.Password != req.ConfirmPassword {
		return nil, errConstant.ErrPasswordDidNotMatch
	}

	user, err := u.repository.GetUser().Register(ctx, &dto.RegisterRequest{
		Name:     req.Name,
		Username: req.Username,
		Password: string(hashedPassword),
		Emial:    req.Emial,
		RoleID:   constants.Customer,
	})
	if err != nil {
		return nil, err
	}

	response := &dto.RegisterResponse{
		User: dto.UserResponse{
			UUID:        user.UUID,
			Name:        user.Name,
			Username:    user.Username,
			PhoneNumber: user.PhoneNumber,
			Email:       user.Email,
		},
	}

	return response, nil
}
