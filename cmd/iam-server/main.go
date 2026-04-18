package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"

	iam "openiam/pkg"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")

	v.SetEnvPrefix("IAM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	v.SetDefault("server.addr", ":8080")
	v.SetDefault("database.dsn", "postgres://postgres:postgres@localhost:5432/iam?sslmode=disable")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("jwt.secret", "change-me-in-production")
	v.SetDefault("jwt.issuer", "openiam")
	v.SetDefault("jwt.access_ttl", "15m")
	v.SetDefault("jwt.refresh_ttl", "168h")
	v.SetDefault("session.ttl", "168h")
	v.SetDefault("siwe.domain", "")
	v.SetDefault("webauthn.rp_id", "")
	v.SetDefault("webauthn.rp_name", "OpenIAM")
	v.SetDefault("webauthn.rp_origins", "")

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			logger.Info("no config file found, using defaults and env vars")
		} else {
			logger.Error("failed to read config file", "error", err)
			os.Exit(1)
		}
	}

	accessTTL, err := time.ParseDuration(v.GetString("jwt.access_ttl"))
	if err != nil {
		logger.Error("invalid jwt.access_ttl", "error", err)
		os.Exit(1)
	}
	refreshTTL, err := time.ParseDuration(v.GetString("jwt.refresh_ttl"))
	if err != nil {
		logger.Error("invalid jwt.refresh_ttl", "error", err)
		os.Exit(1)
	}
	sessionTTL, err := time.ParseDuration(v.GetString("session.ttl"))
	if err != nil {
		logger.Error("invalid session.ttl", "error", err)
		os.Exit(1)
	}

	cfg := iam.Config{
		DatabaseDSN:     v.GetString("database.dsn"),
		RedisAddr:       v.GetString("redis.addr"),
		RedisPassword:   v.GetString("redis.password"),
		RedisDB:         v.GetInt("redis.db"),
		JWTSecret:       v.GetString("jwt.secret"),
		JWTIssuer:       v.GetString("jwt.issuer"),
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
		SessionTTL:      sessionTTL,
		SIWEDomain:      v.GetString("siwe.domain"),
		WebAuthnRPID:    v.GetString("webauthn.rp_id"),
		WebAuthnRPName:  v.GetString("webauthn.rp_name"),
		WebAuthnRPOrigins: splitAndTrim(
			v.GetString("webauthn.rp_origins"),
		),
	}

	engine, err := iam.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize engine", "error", err)
		os.Exit(1)
	}
	defer engine.Close()

	addr := v.GetString("server.addr")
	server := &http.Server{
		Addr:              addr,
		Handler:           engine.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("starting iam-server", "addr", addr)

	go func() {
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", serveErr)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

func splitAndTrim(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
