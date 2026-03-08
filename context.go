package audit

// ContextKey represents a key for storing audit-related values in context.Context
// Using a custom type prevents collisions with other packages
type ContextKey string

const (
	// ContextKeyUserID stores the authenticated user's ID in context
	// This is populated by the audit context middleware after JWT validation
	// Type: uuid.UUID (not *uuid.UUID)
	ContextKeyUserID ContextKey = "audit_user_id"
)
