package application

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"brothers-backend/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = domain.ErrUnauthorized

type RefreshSessionRepository interface {
	CreateRefreshSession(context.Context, string, string, time.Time) error
	RotateRefreshSession(context.Context, string, string, string, time.Time) error
	RevokeRefreshSession(context.Context, string, string) error
}

type AdminPasswordRepository interface {
	GetAdminPasswordHash(context.Context) ([]byte, error)
	EnsureAdminPasswordHash(context.Context, []byte) error
	ChangeAdminPassword(context.Context, []byte, []byte) error
}

type TokenPair struct {
	TokenType    string `json:"tokenType"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
}

type tokenClaims struct {
	Subject string `json:"sub"`
	Type    string `json:"type"`
	Expires int64  `json:"exp"`
	Issued  int64  `json:"iat"`
	ID      string `json:"jti"`
}

type AuthService struct {
	username     string
	passwordHash []byte
	secret       []byte
	sessions     RefreshSessionRepository
	passwords    AdminPasswordRepository
	accessTTL    time.Duration
	refreshTTL   time.Duration
	now          func() time.Time
}

func NewAuthService(username string, passwordHash, secret []byte, sessions RefreshSessionRepository, passwords AdminPasswordRepository) *AuthService {
	return &AuthService{
		username: username, passwordHash: passwordHash, secret: secret, sessions: sessions,
		passwords: passwords,
		accessTTL: 15 * time.Minute, refreshTTL: 7 * 24 * time.Hour, now: time.Now,
	}
}

func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func (s *AuthService) InitializeAdminPassword(ctx context.Context) error {
	_, err := s.passwords.GetAdminPasswordHash(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("load admin password hash: %w", err)
	}
	if len(s.passwordHash) == 0 {
		return errors.New("ADMIN_PASSWORD is required because no admin password is stored in the database")
	}
	if err := s.passwords.EnsureAdminPasswordHash(ctx, s.passwordHash); err != nil {
		return fmt.Errorf("initialize admin password hash: %w", err)
	}
	return nil
}

func (s *AuthService) Login(ctx context.Context, username, password string) (TokenPair, error) {
	if username != s.username {
		return TokenPair{}, ErrUnauthorized
	}
	passwordHash, err := s.passwords.GetAdminPasswordHash(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenPair{}, ErrUnauthorized
		}
		return TokenPair{}, fmt.Errorf("load admin password hash: %w", err)
	}
	if bcrypt.CompareHashAndPassword(passwordHash, []byte(password)) != nil {
		return TokenPair{}, ErrUnauthorized
	}
	pair, refreshHash, expiresAt, err := s.issueTokens(username)
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.sessions.CreateRefreshSession(ctx, refreshHash, username, expiresAt); err != nil {
		return TokenPair{}, fmt.Errorf("save refresh session: %w", err)
	}
	return pair, nil
}

func (s *AuthService) ChangePassword(ctx context.Context, currentPassword, newPassword string) error {
	if len([]byte(newPassword)) < 12 || len([]byte(newPassword)) > 72 {
		return fmt.Errorf("%w: password must be between 12 and 72 bytes", domain.ErrInvalid)
	}
	currentHash, err := s.passwords.GetAdminPasswordHash(ctx)
	if err != nil {
		return fmt.Errorf("load admin password hash: %w", err)
	}
	if bcrypt.CompareHashAndPassword(currentHash, []byte(currentPassword)) != nil {
		return ErrUnauthorized
	}
	newHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new admin password: %w", err)
	}
	if err := s.passwords.ChangeAdminPassword(ctx, currentHash, newHash); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return ErrUnauthorized
		}
		return fmt.Errorf("save new admin password: %w", err)
	}
	return nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return TokenPair{}, ErrUnauthorized
	}
	pair, newHash, expiresAt, err := s.issueTokens(claims.Subject)
	if err != nil {
		return TokenPair{}, err
	}
	oldHash := hashToken(refreshToken)
	if err := s.sessions.RotateRefreshSession(ctx, oldHash, newHash, claims.Subject, expiresAt); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return TokenPair{}, ErrUnauthorized
		}
		return TokenPair{}, fmt.Errorf("rotate refresh session: %w", err)
	}
	return pair, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return ErrUnauthorized
	}
	if err := s.sessions.RevokeRefreshSession(ctx, hashToken(refreshToken), claims.Subject); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return ErrUnauthorized
		}
		return fmt.Errorf("revoke refresh session: %w", err)
	}
	return nil
}

func (s *AuthService) ValidateAccessToken(token string) error {
	_, err := s.parseToken(token, "access")
	if err != nil {
		return ErrUnauthorized
	}
	return nil
}

func (s *AuthService) issueTokens(username string) (TokenPair, string, time.Time, error) {
	now := s.now()
	accessID, err := randomID()
	if err != nil {
		return TokenPair{}, "", time.Time{}, err
	}
	access, err := s.signToken(tokenClaims{
		Subject: username, Type: "access", Issued: now.Unix(),
		Expires: now.Add(s.accessTTL).Unix(), ID: accessID,
	})
	if err != nil {
		return TokenPair{}, "", time.Time{}, err
	}
	refreshExpiry := now.Add(s.refreshTTL)
	refreshID, err := randomID()
	if err != nil {
		return TokenPair{}, "", time.Time{}, err
	}
	refresh, err := s.signToken(tokenClaims{
		Subject: username, Type: "refresh", Issued: now.Unix(),
		Expires: refreshExpiry.Unix(), ID: refreshID,
	})
	if err != nil {
		return TokenPair{}, "", time.Time{}, err
	}
	return TokenPair{
		TokenType: "Bearer", AccessToken: access, RefreshToken: refresh,
		ExpiresIn: int64(s.accessTTL.Seconds()),
	}, hashToken(refresh), refreshExpiry, nil
}

func (s *AuthService) signToken(claims tokenClaims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + signature, nil
}

func (s *AuthService) parseToken(token, expectedType string) (tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenClaims{}, ErrUnauthorized
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return tokenClaims{}, ErrUnauthorized
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "HS256" || header.Type != "JWT" {
		return tokenClaims{}, ErrUnauthorized
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return tokenClaims{}, ErrUnauthorized
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return tokenClaims{}, ErrUnauthorized
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, ErrUnauthorized
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil ||
		claims.Subject == "" || claims.ID == "" || claims.Type != expectedType ||
		claims.Expires <= s.now().Unix() || claims.Issued > s.now().Add(time.Minute).Unix() {
		return tokenClaims{}, ErrUnauthorized
	}
	return claims, nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
