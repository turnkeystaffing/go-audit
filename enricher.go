package audit

import "context"

// Enricher is a function that adds contextual metadata to an audit event.
// Enrichers receive a mutable event pointer and add data to the Metadata map.
//
// Enrichers must:
//   - Complete within 100ms to meet overall <10ms overhead target (with 5-10 enrichers)
//   - Be idempotent (safe to call multiple times)
//   - Handle missing data gracefully (use defaults or skip enrichment)
//   - Return errors instead of panicking
//   - Use context for cancellation/timeout
//
// Enrichers must NOT:
//   - Mutate event.ID, event.Timestamp, event.Action, or event.Outcome
//   - Modify existing keys in event.Metadata (only add new keys)
//   - Block for extended periods
//
// Example enricher that adds user context:
//
//	func EnrichUserContext(userRepo UserRepository) audit.Enricher {
//	    return func(ctx context.Context, event *audit.AuditEvent) error {
//	        user, err := userRepo.FindByID(event.UserID)
//	        if err != nil {
//	            return fmt.Errorf("user enrichment failed: %w", err)
//	        }
//
//	        event.Metadata["user"] = map[string]interface{}{
//	            "role": user.Roles,
//	            "account_status": user.Status,
//	            "email_count": user.EmailCount,
//	        }
//	        return nil
//	    }
//	}
type Enricher func(ctx context.Context, event *AuditEvent) error
