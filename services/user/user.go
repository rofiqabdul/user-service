package services

import (
	"context"
	"strings"
	"time"
	"user-service/config"
	"user-service/domain/dto"
	"user-service/repositories"

	"github.com/golang-jwt/jwt/v5"
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
