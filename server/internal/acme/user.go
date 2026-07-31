package acme

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// ACMEUser implements the lego registration.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func NewACMEUser(email string, key crypto.PrivateKey) *ACMEUser {
	return &ACMEUser{
		Email: email,
		key:   key,
	}
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
