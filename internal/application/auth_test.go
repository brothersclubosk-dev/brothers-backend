package application

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"brothers-backend/internal/domain"
)

type memorySessions struct {
	sessions     map[string]string
	passwordHash []byte
}

func newMemorySessions() *memorySessions {
	return &memorySessions{sessions: make(map[string]string)}
}

func (m *memorySessions) CreateRefreshSession(_ context.Context, hash, username string, _ time.Time) error {
	m.sessions[hash] = username
	return nil
}

func (m *memorySessions) RotateRefreshSession(_ context.Context, oldHash, newHash, username string, _ time.Time) error {
	if m.sessions[oldHash] != username {
		return ErrUnauthorized
	}
	delete(m.sessions, oldHash)
	m.sessions[newHash] = username
	return nil
}

func (m *memorySessions) RevokeRefreshSession(_ context.Context, hash, username string) error {
	if m.sessions[hash] != username {
		return ErrUnauthorized
	}
	delete(m.sessions, hash)
	return nil
}

func (m *memorySessions) GetAdminPasswordHash(_ context.Context) ([]byte, error) {
	if m.passwordHash == nil {
		return nil, domain.ErrNotFound
	}
	return append([]byte(nil), m.passwordHash...), nil
}

func (m *memorySessions) EnsureAdminPasswordHash(_ context.Context, hash []byte) error {
	if m.passwordHash == nil {
		m.passwordHash = append([]byte(nil), hash...)
	}
	return nil
}

func (m *memorySessions) ChangeAdminPassword(_ context.Context, currentHash, newHash []byte) error {
	if !bytes.Equal(m.passwordHash, currentHash) {
		return ErrUnauthorized
	}
	m.passwordHash = append([]byte(nil), newHash...)
	clear(m.sessions)
	return nil
}

func TestAuthRefreshRotationAndLogout(t *testing.T) {
	passwordHash, err := HashPassword("test-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	sessions := newMemorySessions()
	service := NewAuthService("admin", passwordHash, []byte("01234567890123456789012345678901"), sessions, sessions)
	if err := service.InitializeAdminPassword(context.Background()); err != nil {
		t.Fatal(err)
	}

	tokens, err := service.Login(context.Background(), "admin", "test-password-long-enough")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := service.ValidateAccessToken(tokens.AccessToken); err != nil {
		t.Fatalf("validate access token: %v", err)
	}

	rotated, err := service.Refresh(context.Background(), tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := service.Refresh(context.Background(), tokens.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected old refresh token to be rejected, got %v", err)
	}
	if err := service.Logout(context.Background(), rotated.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := service.Refresh(context.Background(), rotated.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected logged-out refresh token to be rejected, got %v", err)
	}
}

func TestAuthRejectsInvalidCredentialsAndTokenType(t *testing.T) {
	passwordHash, err := HashPassword("test-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	sessions := newMemorySessions()
	service := NewAuthService("admin", passwordHash, []byte("01234567890123456789012345678901"), sessions, sessions)
	if err := service.InitializeAdminPassword(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "admin", "wrong-password"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected invalid credentials to be rejected, got %v", err)
	}
	tokens, err := service.Login(context.Background(), "admin", "test-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateAccessToken(tokens.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected refresh token to be rejected as access token, got %v", err)
	}
}

func TestChangePasswordUsesStoredHashAndRevokesRefreshTokens(t *testing.T) {
	oldHash, err := HashPassword("initial-password-long")
	if err != nil {
		t.Fatal(err)
	}
	sessions := newMemorySessions()
	service := NewAuthService("admin", oldHash, []byte("01234567890123456789012345678901"), sessions, sessions)
	if err := service.InitializeAdminPassword(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldTokens, err := service.Login(context.Background(), "admin", "initial-password-long")
	if err != nil {
		t.Fatal(err)
	}

	if err := service.ChangePassword(context.Background(), "wrong-password", "new-password-is-long"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected wrong current password to be rejected, got %v", err)
	}
	if err := service.ChangePassword(context.Background(), "initial-password-long", "new-password-is-long"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := service.Refresh(context.Background(), oldTokens.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected password change to revoke refresh token, got %v", err)
	}
	if _, err := service.Login(context.Background(), "admin", "initial-password-long"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected old password to be rejected, got %v", err)
	}
	if _, err := service.Login(context.Background(), "admin", "new-password-is-long"); err != nil {
		t.Fatalf("login with changed password: %v", err)
	}
	if err := service.ChangePassword(context.Background(), "new-password-is-long", "short"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("expected short new password to be rejected, got %v", err)
	}
}
