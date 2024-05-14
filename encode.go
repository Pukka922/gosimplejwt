package gosimplejwt

import "github.com/golang-jwt/jwt/v5"

func Encode(jwtValues map[string]interface{}, signKey string) (string, error) {

	clientValues := make(jwt.MapClaims)

	for key, value := range jwtValues {
		clientValues[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &clientValues)

	tokenString, err := token.SignedString([]byte(signKey))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}
