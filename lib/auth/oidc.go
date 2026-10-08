/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

type OIDCService interface {
	CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error)
	CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error)
	ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error)
}

// ErrOIDCNoRoles is returned when an OIDC user has no Teleport-assigned roles.
var ErrOIDCNoRoles = trace.AccessDenied("OIDC user has no Teleport-assigned roles.")

// UpsertOIDCConnector creates or updates an OIDC connector.
func (a *Server) UpsertOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	upserted, err := a.Services.UpsertOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorCreate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorCreatedEvent,
			Code: events.OIDCConnectorCreatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		a.logger.WarnContext(ctx, "Failed to emit OIDC connector create event", "error", err)
	}

	return upserted, nil
}

// UpdateOIDCConnector updates an existing OIDC connector.
func (a *Server) UpdateOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	updated, err := a.Services.UpdateOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorUpdate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorUpdatedEvent,
			Code: events.OIDCConnectorUpdatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		a.logger.WarnContext(ctx, "Failed to emit OIDC connector update event", "error", err)
	}

	return updated, nil
}

// CreateOIDCConnector creates a new OIDC connector.
func (a *Server) CreateOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	created, err := a.Services.CreateOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorCreate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorCreatedEvent,
			Code: events.OIDCConnectorCreatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		a.logger.WarnContext(ctx, "Failed to emit OIDC connector create event", "error", err)
	}

	return created, nil
}

// DeleteOIDCConnector deletes an OIDC connector by name.
func (a *Server) DeleteOIDCConnector(ctx context.Context, connectorName string) error {
	if err := a.Services.DeleteOIDCConnector(ctx, connectorName); err != nil {
		return trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorDelete{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorDeletedEvent,
			Code: events.OIDCConnectorDeletedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connectorName,
		},
	}); err != nil {
		a.logger.WarnContext(ctx, "Failed to emit OIDC connector delete event", "error", err)
	}
	return nil
}

func (a *Server) getOrCreateOIDCAuthService() OIDCService {
	if a.oidcAuthService == nil {
		a.oidcAuthService = newDefaultOIDCAuthService(a)
	}
	return a.oidcAuthService
}

// CreateOIDCAuthRequest delegates the method call to the oidcAuthService.
func (a *Server) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	rq, err := a.getOrCreateOIDCAuthService().CreateOIDCAuthRequest(ctx, req)
	return rq, trace.Wrap(err)
}

// CreateOIDCAuthRequestForMFA delegates the method call to the oidcAuthService.
func (a *Server) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	rq, err := a.getOrCreateOIDCAuthService().CreateOIDCAuthRequestForMFA(ctx, req)
	return rq, trace.Wrap(err)
}

// ValidateOIDCAuthCallback delegates the method call to the oidcAuthService.
func (a *Server) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	resp, err := a.getOrCreateOIDCAuthService().ValidateOIDCAuthCallback(ctx, q)
	return resp, trace.Wrap(err)
}

// DefaultOIDCAuthService provides an OIDCService implementation.
type DefaultOIDCAuthService struct {
	auth      *Server
	emitter   apievents.Emitter
	logger    *slog.Logger
	mu        sync.RWMutex
	providers map[string]*cachedOIDCProvider
}

type cachedOIDCProvider struct {
	provider  *oidc.Provider
	expiresAt time.Time
}

func newDefaultOIDCAuthService(auth *Server) *DefaultOIDCAuthService {
	return &DefaultOIDCAuthService{
		auth:      auth,
		emitter:   auth.emitter,
		logger:    auth.logger.With(teleport.ComponentKey, "oidc"),
		providers: make(map[string]*cachedOIDCProvider),
	}
}

func (s *DefaultOIDCAuthService) oidcContext(ctx context.Context) context.Context {
	if s.auth.insecureMode {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		return oidc.ClientContext(ctx, cl)
	}
	return ctx
}

func (s *DefaultOIDCAuthService) getProvider(ctx context.Context, issuerURL string) (*oidc.Provider, error) {
	s.mu.RLock()
	if cp, ok := s.providers[issuerURL]; ok && time.Now().Before(cp.expiresAt) {
		s.mu.RUnlock()
		return cp.provider, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if cp, ok := s.providers[issuerURL]; ok && time.Now().Before(cp.expiresAt) {
		return cp.provider, nil
	}

	p, err := oidc.NewProvider(s.oidcContext(ctx), issuerURL)
	if err != nil {
		return nil, trace.Wrap(err, "failed to query OIDC provider configuration from %q", issuerURL)
	}

	s.providers[issuerURL] = &cachedOIDCProvider{
		provider:  p,
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	return p, nil
}

func (s *DefaultOIDCAuthService) getConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec cannot be nil for SSOTestFlow")
		}
		if req.ConnectorID == "" {
			return nil, trace.BadParameter("ConnectorID cannot be empty")
		}
		return types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
	}
	return s.auth.GetOIDCConnector(ctx, req.ConnectorID, true)
}

func (s *DefaultOIDCAuthService) oauth2Config(connector types.OIDCConnector, provider *oidc.Provider, redirectURL string) *oauth2.Config {
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	seen := map[string]bool{oidc.ScopeOpenID: true, "profile": true, "email": true}
	for _, sc := range connector.GetScope() {
		if sc != "" && !seen[sc] {
			scopes = append(scopes, sc)
			seen[sc] = true
		}
	}
	return &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}
}

func (s *DefaultOIDCAuthService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	provider, err := s.getProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	conf := s.oauth2Config(connector, provider, redirectURL)

	stateToken, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.StateToken = stateToken

	if req.PkceVerifier == "" && connector.GetPKCEMode() != constants.OIDCPKCEModeDisabled {
		req.PkceVerifier = oauth2.GenerateVerifier()
	}

	authCodeOpts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
	}
	if req.PkceVerifier != "" {
		authCodeOpts = append(authCodeOpts, oauth2.S256ChallengeOption(req.PkceVerifier))
	}
	if connector.GetPrompt() != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("prompt", connector.GetPrompt()))
	}
	if req.LoginHint != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}
	if connector.GetACR() != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("acr_values", connector.GetACR()))
	}

	req.RedirectURL = conf.AuthCodeURL(req.StateToken, authCodeOpts...)

	if err := s.auth.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (s *DefaultOIDCAuthService) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	req.SSOTestFlow = false
	return s.CreateOIDCAuthRequest(ctx, req)
}

func (s *DefaultOIDCAuthService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindOIDC, s.auth)
	return s.validateOIDCAuthCallbackHelper(ctx, diagCtx, q)
}

func (s *DefaultOIDCAuthService) validateOIDCAuthCallbackHelper(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error) {
	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodOIDC,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	authResp, err := s.validateOIDCAuthCallbackRedirect(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	claims := diagCtx.Info.OIDCClaims
	if claims != nil {
		if attributes, errEncode := apievents.EncodeMap(claims); errEncode != nil {
			s.logger.DebugContext(ctx, "Failed to encode identity attributes", "error", errEncode)
		} else {
			event.IdentityAttributes = attributes
		}
	}

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if errEmit := s.emitter.EmitAuditEvent(ctx, event); errEmit != nil {
			s.logger.WarnContext(ctx, "Failed to emit OIDC login failed event", "error", errEmit)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = authResp.Username

	if errEmit := s.emitter.EmitAuditEvent(ctx, event); errEmit != nil {
		s.logger.WarnContext(ctx, "Failed to emit OIDC login event", "error", errEmit)
	}

	return authResp, nil
}

func (s *DefaultOIDCAuthService) validateOIDCAuthCallbackRedirect(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error) {
	if errParam := q.Get("error"); errParam != "" {
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := s.auth.Services.GetOIDCAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "OIDC provider returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("invalid_request", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("invalid_request", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}
	diagCtx.RequestID = stateToken

	req, err := s.auth.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, err := s.getConnector(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC connector.")
	}

	provider, err := s.getProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	conf := s.oauth2Config(connector, provider, redirectURL)

	var exchangeOpts []oauth2.AuthCodeOption
	if req.PkceVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(req.PkceVerifier))
	}
	oidcCtx := s.oidcContext(ctx)
	token, err := conf.Exchange(oidcCtx, code, exchangeOpts...)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to exchange authorization code for token")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, trace.BadParameter("No id_token in OIDC token response")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: connector.GetClientID()})
	idToken, err := verifier.Verify(oidcCtx, rawIDToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to verify OIDC ID token")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, trace.Wrap(err, "Failed to extract claims from ID token")
	}

	userInfo, err := provider.UserInfo(oidcCtx, oauth2.StaticTokenSource(token))
	if err == nil && userInfo != nil {
		var userClaims map[string]any
		if err := userInfo.Claims(&userClaims); err == nil {
			if sub1, ok1 := claims["sub"].(string); ok1 {
				if sub2, ok2 := userClaims["sub"].(string); ok2 && sub1 != sub2 {
					return nil, trace.BadParameter("OIDC sub claim in userinfo (%s) does not match id_token (%s)", sub2, sub1)
				}
			}
			for k, v := range userClaims {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	}

	diagCtx.Info.OIDCClaims = types.OIDCClaims(claims)

	if !connector.GetAllowUnverifiedEmail() {
		if err := checkEmailVerifiedClaim(claims); err != nil {
			return nil, trace.Wrap(err, "OIDC provider did not verify email")
		}
	}

	if connector.GetACR() != "" {
		if err := validateACR(connector.GetACR(), claims); err != nil {
			return nil, trace.Wrap(err, "OIDC ACR validation failed")
		}
	}

	username, err := usernameFromClaims(connector, claims)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	traits := oidcClaimsToTraits(claims)
	traits[constants.TraitLogins] = append(traits[constants.TraitLogins], username)

	diagCtx.Info.OIDCTraitsFromClaims = traits
	diagCtx.Info.OIDCConnectorTraitMapping = connector.GetTraitMappings()

	evalInput := &loginrule.EvaluationInput{Traits: traits}
	evalOutput, err := s.auth.GetLoginRuleEvaluator().Evaluate(ctx, evalInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	traits = evalOutput.Traits
	diagCtx.Info.AppliedLoginRules = evalOutput.AppliedRules

	warnings, roles := services.TraitsToRoles(connector.GetTraitMappings(), traits)
	if len(roles) == 0 {
		diagCtx.Info.OIDCClaimsToRolesWarnings = &types.SSOWarnings{
			Message:  "No roles mapped for the user. Check claims_to_roles mappings in connector.",
			Warnings: warnings,
		}
		return nil, trace.Wrap(ErrOIDCNoRoles)
	}

	fetchedRoles, err := services.FetchRolesWithContext(roles, s.auth, services.RoleTemplateContext{
		Username: username,
		Traits:   traits,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := fetchedRoles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	sessionTTL := utils.MinTTL(roleTTL, req.CertTTL)

	userParams := &CreateUserParams{
		ConnectorName: connector.GetName(),
		Username:      username,
		Roles:         roles,
		Traits:        traits,
		SessionTTL:    sessionTTL,
	}
	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: userParams.ConnectorName,
		Username:      userParams.Username,
		Roles:         userParams.Roles,
		Traits:        userParams.Traits,
		SessionTTL:    types.Duration(userParams.SessionTTL),
	}

	user, err := s.createOIDCUser(ctx, userParams, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create/update OIDC user")
	}

	if err := s.auth.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := s.auth.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &authclient.OIDCAuthResponse{
			Req: OIDCAuthRequestFromProto(req),
			Identity: types.ExternalIdentity{
				ConnectorID: connector.GetName(),
				Username:    username,
			},
			Username: username,
		}, nil
	}

	return s.makeOIDCAuthResponse(ctx, req, userState, connector.GetName(), sessionTTL)
}

func (s *DefaultOIDCAuthService) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	s.logger.DebugContext(ctx, "Generating dynamic OIDC identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"roles", p.Roles,
		"dry_run", dryRun,
	)

	expires := s.auth.clock.Now().UTC().Add(p.SessionTTL)
	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.auth.clock.Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := s.auth.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user", existingUser.GetName())
		}
		user.SetRevision(existingUser.GetRevision())
		if _, err := s.auth.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := s.auth.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

func (s *DefaultOIDCAuthService) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	connectorName string,
	sessionTTL time.Duration,
) (*authclient.OIDCAuthResponse, error) {
	resp := authclient.OIDCAuthResponse{
		Req: OIDCAuthRequestFromProto(req),
		Identity: types.ExternalIdentity{
			ConnectorID: connectorName,
			Username:    userState.GetName(),
		},
		Username: userState.GetName(),
	}

	if req.CreateWebSession {
		session, err := s.auth.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            s.auth.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session")
		}
		resp.Session = session
	}

	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := s.auth.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificates")
		}

		clusterName, err := s.auth.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to get cluster name")
		}
		resp.Cert = sshCert
		resp.TLSCert = tlsCert

		authority, err := s.auth.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain host CA")
		}
		resp.HostSigners = append(resp.HostSigners, authority)
	}

	if o, err := s.auth.ClientOptionsForLogin(userState); err == nil {
		resp.ClientOptions = o
	} else {
		s.logger.WarnContext(ctx, "Failed to calculate client options for OIDC login", "username", userState.GetName(), "error", err)
	}

	return &resp, nil
}

func usernameFromClaims(connector types.OIDCConnector, claims map[string]any) (string, error) {
	claimName := connector.GetUsernameClaim()
	if claimName != "" {
		if val, ok := claims[claimName]; ok {
			if strVal, isStr := val.(string); isStr && strVal != "" {
				return strVal, nil
			}
			return "", trace.BadParameter("Configured username_claim %q in connector %q is not a valid non-empty string", claimName, connector.GetName())
		}
		return "", trace.BadParameter("Configured username_claim %q was not found in claims from OIDC provider for connector %q", claimName, connector.GetName())
	}

	if email, ok := claims["email"].(string); ok && email != "" {
		return email, nil
	}
	if pref, ok := claims["preferred_username"].(string); ok && pref != "" {
		return pref, nil
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub, nil
	}

	return "", trace.BadParameter("Unable to determine username from OIDC claims for connector %q. Configure username_claim explicitly.", connector.GetName())
}

func checkEmailVerifiedClaim(claims map[string]any) error {
	v, ok := claims["email_verified"]
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case bool:
		if !val {
			return trace.AccessDenied("email not verified by OIDC provider")
		}
	case string:
		if val == "false" {
			return trace.AccessDenied("email not verified by OIDC provider")
		}
	}
	return nil
}

func validateACR(expectedACR string, claims map[string]any) error {
	v, ok := claims["acr"]
	if !ok {
		return trace.BadParameter("acr claim missing from ID token")
	}
	if acrStr, ok := v.(string); ok && acrStr == expectedACR {
		return nil
	}
	return trace.BadParameter("expected acr %q, got %v", expectedACR, v)
}

func oidcClaimsToTraits(claims map[string]any) map[string][]string {
	traits := make(map[string][]string)
	for k, v := range claims {
		switch val := v.(type) {
		case string:
			traits[k] = []string{val}
		case []string:
			traits[k] = val
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					traits[k] = append(traits[k], s)
				}
			}
		}
	}
	return traits
}

func OIDCAuthRequestFromProto(req *types.OIDCAuthRequest) authclient.OIDCAuthRequest {
	return authclient.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		CSRFToken:         req.CSRFToken,
		PublicKey:         req.SshPublicKey,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
	}
}
