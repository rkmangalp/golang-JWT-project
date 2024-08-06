package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// checkUserType checks if the user type from the context matches the required role.
// Returns an error if the user type does not match the role.
func CheckUserType(c *gin.Context, role string) (err error) {
	// Get the user type from the context.
	userType := c.GetString("user_type")
	err = nil

	// If the user type does not match the required role, return an error.
	if userType != role {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	// If the user type matches the role, return nil.
	return err
}

// MatchUserTypeToUid checks if the user type and user ID from the context match the given user ID.
// Returns an error if the user type is "USER" and the user ID does not match.
func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	// Get the user type and user ID from the context.
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	// If the user type is "USER" and the user ID does not match, return an error.
	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	// Check if the user type matches the required role.
	err = CheckUserType(c, userType)
	return err
}
