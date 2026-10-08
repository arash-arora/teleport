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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestUsernameFromClaims(t *testing.T) {
	connector, err := types.NewOIDCConnector("authentik", types.OIDCConnectorSpecV3{
		IssuerURL:    "https://auth.example.com/application/o/teleport/",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
	})
	require.NoError(t, err)

	// Default fallback to email
	u, err := usernameFromClaims(connector, map[string]any{
		"email": "user@example.com",
		"sub":   "12345",
	})
	require.NoError(t, err)
	require.Equal(t, "user@example.com", u)

	// Default fallback to preferred_username
	u, err = usernameFromClaims(connector, map[string]any{
		"preferred_username": "akash",
		"sub":                "12345",
	})
	require.NoError(t, err)
	require.Equal(t, "akash", u)

	// Default fallback to sub
	u, err = usernameFromClaims(connector, map[string]any{
		"sub": "12345",
	})
	require.NoError(t, err)
	require.Equal(t, "12345", u)

	// Custom username_claim specified
	connectorWithClaim, err := types.NewOIDCConnector("authentik", types.OIDCConnectorSpecV3{
		IssuerURL:     "https://auth.example.com/application/o/teleport/",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		RedirectURLs:  []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		UsernameClaim: "nickname",
	})
	require.NoError(t, err)

	u, err = usernameFromClaims(connectorWithClaim, map[string]any{
		"nickname": "custom-nick",
		"email":    "user@example.com",
	})
	require.NoError(t, err)
	require.Equal(t, "custom-nick", u)

	// Missing configured username claim fails
	_, err = usernameFromClaims(connectorWithClaim, map[string]any{
		"email": "user@example.com",
	})
	require.Error(t, err)
}

func TestCheckEmailVerifiedClaim(t *testing.T) {
	// Not present -> allowed
	require.NoError(t, checkEmailVerifiedClaim(map[string]any{}))

	// True boolean
	require.NoError(t, checkEmailVerifiedClaim(map[string]any{"email_verified": true}))

	// True string
	require.NoError(t, checkEmailVerifiedClaim(map[string]any{"email_verified": "true"}))

	// False boolean
	require.Error(t, checkEmailVerifiedClaim(map[string]any{"email_verified": false}))

	// False string
	require.Error(t, checkEmailVerifiedClaim(map[string]any{"email_verified": "false"}))
}

func TestValidateACR(t *testing.T) {
	require.NoError(t, validateACR("phr", map[string]any{"acr": "phr"}))
	require.Error(t, validateACR("phr", map[string]any{"acr": "other"}))
	require.Error(t, validateACR("phr", map[string]any{}))
}

func TestOIDCClaimsToTraits(t *testing.T) {
	claims := map[string]any{
		"email":  "test@example.com",
		"groups": []any{"admins", "devs"},
		"roles":  []string{"operator"},
	}

	traits := oidcClaimsToTraits(claims)
	require.Equal(t, []string{"test@example.com"}, traits["email"])
	require.Equal(t, []string{"admins", "devs"}, traits["groups"])
	require.Equal(t, []string{"operator"}, traits["roles"])
}
