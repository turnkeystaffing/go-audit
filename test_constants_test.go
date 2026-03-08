package audit

// Test-only action and resource type constants.
const (
	testActionLogin          = "login"
	testActionLogout         = "logout"
	testActionPasswordReset  = "password.reset"
	testActionPasswordChange = "password.change"
	testActionTokenRefresh   = "token.refresh"

	testResourceTypeSession = "session"
	testResourceTypeUser    = "user"
	testResourceTypeToken   = "token"
)
