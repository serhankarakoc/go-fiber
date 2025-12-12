package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"zatrano/configs/logconfig"
	"zatrano/configs/sessionconfig"
	"zatrano/packages/flashmessages"
	"zatrano/services"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleAuthHandler struct {
	authService services.IAuthService
	oauthConfig *oauth2.Config
}

func NewGoogleAuthHandler() *GoogleAuthHandler {
	return &GoogleAuthHandler{
		authService: services.NewAuthService(),
		oauthConfig: &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URI"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (h *GoogleAuthHandler) generateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (h *GoogleAuthHandler) GoogleLogin(c *fiber.Ctx) error {
	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Google login: Oturum başlatılamadı", zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum başlatılamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	stateToken, err := h.generateToken()
	if err != nil {
		logconfig.Log.Error("Google login: State token oluşturulamadı", zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"State token oluşturulamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	sess.Set("oauth_state", stateToken)
	sess.Set("oauth_provider", "google")

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Google login: Session kaydedilemedi", zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	authURL := h.oauthConfig.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	return c.Redirect(authURL, http.StatusTemporaryRedirect)
}

func (h *GoogleAuthHandler) GoogleCallback(c *fiber.Ctx) error {
	state := c.Query("state")
	code := c.Query("code")

	if state == "" || code == "" {
		logconfig.Log.Warn("Google callback: Eksik parametreler",
			zap.String("state", state),
			zap.Bool("has_code", code != ""))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz istek parametreleri.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Google callback: Oturum başlatılamadı", zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum başlatılamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	savedState := sess.Get("oauth_state")
	savedProvider := sess.Get("oauth_provider")

	if savedState != state {
		logconfig.Log.Warn("Google callback: Geçersiz state token",
			zap.String("saved_state", fmt.Sprintf("%v", savedState)),
			zap.String("received_state", state))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz state token.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	if savedProvider != "google" {
		logconfig.Log.Warn("Google callback: Yanlış OAuth provider",
			zap.String("saved_provider", fmt.Sprintf("%v", savedProvider)))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Yanlış OAuth provider.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		logconfig.Log.Error("Google callback: Token exchange failed",
			zap.Error(err),
			zap.String("code", code[:10]+"..."))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Token değişimi başarısız.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	userInfo, err := h.getGoogleUserInfo(token)
	if err != nil {
		logconfig.Log.Error("Google callback: User info alınamadı", zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı bilgileri alınamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	user, err := h.authService.FindOrCreateOAuthUser(
		userInfo.ID,
		userInfo.Email,
		userInfo.Name,
		"google",
	)
	if err != nil {
		logconfig.Log.Error("Google callback: Kullanıcı oluşturulamadı",
			zap.String("email", userInfo.Email),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı oluşturulamadı veya giriş yapılamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	sess.Delete("oauth_state")
	sess.Delete("oauth_provider")

	sess.Set("user_id", user.ID)
	sess.Set("user_type_id", user.UserTypeID)
	sess.Set("is_active", user.IsActive)
	sess.Set("login_method", "google")

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Google callback: Session kaydedilemedi",
			zap.Uint("user_id", user.ID),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	logconfig.Log.Info("Google ile giriş başarılı",
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email))

	flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey,
		"Google ile giriş başarılı.")

	return h.redirectAfterLogin(c, user.UserTypeID)
}

type GoogleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (h *GoogleAuthHandler) getGoogleUserInfo(token *oauth2.Token) (*GoogleUserInfo, error) {
	client := h.oauthConfig.Client(context.Background(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google API hatası: %s", resp.Status)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	if userInfo.Email == "" {
		return nil, errors.New("google'dan email alınamadı")
	}

	return &userInfo, nil
}

func (h *GoogleAuthHandler) redirectAfterLogin(c *fiber.Ctx, userTypeID uint) error {
	switch userTypeID {
	case 1:
		return c.Redirect("/dashboard/home", fiber.StatusSeeOther)
	default:
		return c.Redirect("/panel/anasayfa", fiber.StatusSeeOther)
	}
}
