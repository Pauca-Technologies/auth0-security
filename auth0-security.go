package auth0security

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	jwtMiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

type DefaultCustomClaims struct {
	UserRole           string `json:"user_role"`
	RoleInOrganization string `json:"role_in_organization"`
	Organization       string `json:"organization"`
	OrganizationId     string `json:"organization_id"`
	ginContext         *gin.Context
}

func (c *DefaultCustomClaims) Validate(ctx context.Context) error {
	c.ginContext.Set("user_role", c.UserRole)
	c.ginContext.Set("role_in_organization", c.RoleInOrganization)
	c.ginContext.Set("organization", c.Organization)
	c.ginContext.Set("organization_id", c.OrganizationId)
	return nil
}

func DefaultCustomClaimsConstructor(ginContext *gin.Context) func() validator.CustomClaims {
	customClaims := new(DefaultCustomClaims)
	customClaims.ginContext = ginContext
	return func() validator.CustomClaims {
		return customClaims
	}
}

type CustomClaimsConstructor func(ginContext *gin.Context) func() validator.CustomClaims

func JwtValidator(issuerURL *url.URL,
	cacheTTL time.Duration,
	audience []string,
	customClaimsConstructor CustomClaimsConstructor,
	opts ...interface{}) gin.HandlerFunc {
	provider := jwks.NewCachingProvider(issuerURL, cacheTTL)

	handlerFunction := func(gctx *gin.Context) {
		jwtValidator, err := validator.New(provider.KeyFunc,
			validator.RS256,
			issuerURL.String(),
			audience,
			validator.WithCustomClaims(customClaimsConstructor(gctx)))
		if err != nil {
			panic(err)
		}
		jwtMiddleware := jwtMiddleware.New(jwtValidator.ValidateToken)
		var skip = true
		var handler http.HandlerFunc = func(http.ResponseWriter, *http.Request) {
			skip = false
		}

		jwtMiddleware.CheckJWT(handler).ServeHTTP(gctx.Writer, gctx.Request)
		switch {
		case skip:
			if os.Getenv("ENV") == "local" && len(opts) > 0 {
				if fallbackClaimsValues, ok := opts[0].(map[string]string); ok {
					log.Printf("Validation failed. Local environment. Fallback to default values: %v\n", fallbackClaimsValues)
					for key, value := range fallbackClaimsValues {
						gctx.Set(key, value)
					}
					gctx.Next()
				}
			} else {
				gctx.Abort()
			}
		default:
			gctx.Next()
		}
	}
	return handlerFunction

}
