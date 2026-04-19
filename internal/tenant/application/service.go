package application

import (
	"context"
	"time"

	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/persistence"
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
	txManager  *persistence.TxManager
}

func NewTenantAppService(
	tenantRepo domain.TenantRepository,
	appRepo domain.ApplicationRepository,
	eventBus shared.EventBus,
	txManager *persistence.TxManager,
) *TenantAppService {
	return &TenantAppService{
		tenantRepo: tenantRepo,
		appRepo:    appRepo,
		eventBus:   eventBus,
		txManager:  txManager,
	}
}

func (s *TenantAppService) CreateTenant(ctx context.Context, cmd *command.CreateTenant) (shared.TenantID, error) {
	tenant := domain.NewTenant(cmd.Name)

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
	creds := domain.GenerateClientCredentials()
	createdBy := shared.UserID(cmd.CreatedBy)
	app := domain.NewApplication(tenantID, cmd.Name, creds, createdBy)

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
	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		app, err := s.appRepo.FindByID(txCtx, shared.AppID(cmd.AppID))
		if err != nil {
			return err
		}

		if cmd.Name != "" {
			app.Name = cmd.Name
		}
		if cmd.RedirectURIs != nil {
			app.RedirectURIs = cmd.RedirectURIs
		}
		if cmd.Scopes != nil {
			app.Scopes = cmd.Scopes
		}

		return s.appRepo.Save(txCtx, app)
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
