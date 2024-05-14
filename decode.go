package gosimplejwt

import (
	"errors"
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v5"
)

func DecodeToStruct[T any](jwtString, signeKey string) (*T, error) {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(signeKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result := new(T)

		err = mapstructure.Decode(claims, result)

		if err != nil {
			return nil, err
		}

		return result, nil
	}

	return nil, errors.New("error during encoding")
}
