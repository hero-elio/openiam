package application

import (
	"context"
	"errors"
	"strings"
	"time"

	shared "openiam/internal/shared/domain"
	"openiam/internal/tenant/application/command"
	"openiam/internal/tenant/application/query"
	"openiam/internal/tenant/domain"
)

type TenantDTO struct {
	ID        string
	Name      string
	Status    string
	CreatedAt string
}

type ApplicationDTO struct {
	ID           string
	TenantID     string
	Name         string
	ClientID     string
	RedirectURIs []string
	Scopes       []string
	Status       string
	CreatedAt    string
}

type CreateApplicationResult struct {
	Application  ApplicationDTO
	ClientSecret string
}

type TenantAppService struct {
	tenantRepo domain.TenantRepository
	appRepo    domain.ApplicationRepository
	eventBus   shared.EventBus
	txManager  shared.TxManager
}

func NewTenantAppService(
	tenantRepo domain.TenantRepository,
	appRepo domain.ApplicationRepository,
	eventBus shared.EventBus,
	txManager shared.TxManager,
) *TenantAppService {
	return &TenantAppService{
		tenantRepo: tenantRepo,
		appRepo:    appRepo,
		eventBus:   eventBus,
		txManager:  txManager,
	}
}

func (s *TenantAppService) CreateTenant(ctx context.Context, cmd *command.CreateTenant) (shared.TenantID, error) {
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		return "", shared.ErrInvalidInput
	}
	tenant := domain.NewTenant(name)

	if err := s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.tenantRepo.Save(txCtx, tenant); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, tenant.PullEvents()...)
	}); err != nil {
		return "", err
	}

	return tenant.ID, nil
}

func (s *TenantAppService) GetTenant(ctx context.Context, q *query.GetTenant) (*TenantDTO, error) {
	t, err := s.tenantRepo.FindByID(ctx, shared.TenantID(q.TenantID))
	if err != nil {
		return nil, err
	}
	return toTenantDTO(t), nil
}

func (s *TenantAppService) CreateApplication(ctx context.Context, cmd *command.CreateApplication) (*CreateApplicationResult, error) {
	tenantID := shared.TenantID(cmd.TenantID)
	name := strings.TrimSpace(cmd.Name)
	if tenantID.IsEmpty() || name == "" {
		return nil, shared.ErrInvalidInput
	}
	creds := domain.GenerateClientCredentials()
	createdBy := shared.UserID(cmd.CreatedBy)
	app := domain.NewApplication(tenantID, name, creds, createdBy)

	if err := s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if _, err := s.tenantRepo.FindByID(txCtx, tenantID); err != nil {
			return err
		}
		if err := s.appRepo.Save(txCtx, app); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, app.PullEvents()...)
	}); err != nil {
		return nil, err
	}

	return &CreateApplicationResult{
		Application:  *toAppDTO(app),
		ClientSecret: creds.ClientSecret,
	}, nil
}

func (s *TenantAppService) GetApplication(ctx context.Context, q *query.GetApplication) (*ApplicationDTO, error) {
	app, err := s.appRepo.FindByID(ctx, shared.AppID(q.AppID))
	if err != nil {
		return nil, err
	}
	return toAppDTO(app), nil
}

// AppExists is a thin wrapper around the application repository for
// other contexts (e.g. authz) that need a "does this app exist?"
// pre-check without depending on the tenant domain. Returns
// (false, nil) for a clean miss; only surfaces other errors.
func (s *TenantAppService) AppExists(ctx context.Context, id shared.AppID) (bool, error) {
	if id == "" {
		return false, nil
	}
	_, err := s.appRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *TenantAppService) ListApplications(ctx context.Context, q *query.ListApplications) ([]*ApplicationDTO, error) {
	apps, err := s.appRepo.ListByTenant(ctx, shared.TenantID(q.TenantID))
	if err != nil {
		return nil, err
	}

	dtos := make([]*ApplicationDTO, 0, len(apps))
	for _, app := range apps {
		dtos = append(dtos, toAppDTO(app))
	}
	return dtos, nil
}

func (s *TenantAppService) UpdateApplication(ctx context.Context, cmd *command.UpdateApplication) error {
	if strings.TrimSpace(cmd.AppID) == "" {
		return shared.ErrInvalidInput
	}
	if cmd.Name != "" && strings.TrimSpace(cmd.Name) == "" {
		return shared.ErrInvalidInput
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		app, err := s.appRepo.FindByID(txCtx, shared.AppID(cmd.AppID))
		if err != nil {
			return err
		}

		if !app.ApplyUpdate(domain.ApplicationUpdate{
			Name:         cmd.Name,
			RedirectURIs: cmd.RedirectURIs,
			Scopes:       cmd.Scopes,
		}) {
			return nil
		}

		if err := s.appRepo.Save(txCtx, app); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, app.PullEvents()...)
	})
}

func toTenantDTO(t *domain.Tenant) *TenantDTO {
	return &TenantDTO{
		ID:        t.ID.String(),
		Name:      t.Name,
		Status:    t.Status,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
	}
}

func toAppDTO(app *domain.Application) *ApplicationDTO {
	return &ApplicationDTO{
		ID:           app.ID.String(),
		TenantID:     app.TenantID.String(),
		Name:         app.Name,
		ClientID:     app.ClientID,
		RedirectURIs: app.RedirectURIs,
		Scopes:       app.Scopes,
		Status:       app.Status,
		CreatedAt:    app.CreatedAt.Format(time.RFC3339),
	}
}
