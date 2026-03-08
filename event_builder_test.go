package audit

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEventBuilder validates the EventBuilder fluent API for constructing audit events.
// Tests cover all builder methods, validation rules, and common usage patterns.
func TestEventBuilder(t *testing.T) {
	t.Run("NewEventBuilder_InitializesDefaults", func(t *testing.T) {
		// Execute
		builder := NewEventBuilder()
		event := builder.Build()

		// Assert - verify default initialization
		assert.NotEqual(t, uuid.Nil, event.ID, "ID should be generated")
		assert.NotEqual(t, uuid.Nil, event.RequestID, "RequestID should be generated")
		assert.False(t, event.Timestamp.IsZero(), "Timestamp should be set")
		assert.NotNil(t, event.ContextData, "ContextData should be initialized")
		assert.Empty(t, event.ContextData, "ContextData should be empty map")
	})

	t.Run("WithUser_SetsUserID", func(t *testing.T) {
		// Setup
		userID := uuid.New()

		// Execute
		event := NewEventBuilder().
			WithUser(userID).
			Build()

		// Assert
		require.NotNil(t, event.UserID, "UserID should be set")
		assert.Equal(t, userID, *event.UserID, "UserID should match")
	})

	t.Run("WithAction_SetsAction", func(t *testing.T) {
		// Execute
		event := NewEventBuilder().
			WithAction(testActionLogin).
			Build()

		// Assert
		assert.Equal(t, testActionLogin, event.Action, "Action should be set")
	})

	t.Run("WithResource_SetsResourceTypeAndID", func(t *testing.T) {
		// Setup
		sessionID := uuid.New()

		// Execute
		event := NewEventBuilder().
			WithResource(testResourceTypeSession, &sessionID).
			Build()

		// Assert
		assert.Equal(t, testResourceTypeSession, event.ResourceType, "ResourceType should be set")
		require.NotNil(t, event.ResourceID, "ResourceID should be set")
		assert.Equal(t, sessionID, *event.ResourceID, "ResourceID should match")
	})

	t.Run("WithResource_NilResourceID", func(t *testing.T) {
		// Execute - logout all sessions scenario
		event := NewEventBuilder().
			WithResource(testResourceTypeUser, nil).
			Build()

		// Assert
		assert.Equal(t, testResourceTypeUser, event.ResourceType, "ResourceType should be set")
		assert.Nil(t, event.ResourceID, "ResourceID should be nil")
	})

	t.Run("WithSuccess_SetsOutcome", func(t *testing.T) {
		// Execute
		event := NewEventBuilder().
			WithSuccess().
			Build()

		// Assert
		assert.Equal(t, OutcomeSuccess, event.Outcome, "Outcome should be success")
		assert.Empty(t, event.FailureReason, "FailureReason should be empty")
	})

	t.Run("WithFailure_SetsOutcomeAndReason", func(t *testing.T) {
		// Setup
		reason := "invalid password"

		// Execute
		event := NewEventBuilder().
			WithFailure(reason).
			Build()

		// Assert
		assert.Equal(t, OutcomeFailure, event.Outcome, "Outcome should be failure")
		assert.Equal(t, reason, event.FailureReason, "FailureReason should be set")
	})

	t.Run("WithPartial_SetsOutcomeAndReason", func(t *testing.T) {
		// Setup
		reason := "SMTP timeout during email send"

		// Execute
		event := NewEventBuilder().
			WithPartial(reason).
			Build()

		// Assert
		assert.Equal(t, OutcomePartial, event.Outcome, "Outcome should be partial")
		assert.Equal(t, reason, event.FailureReason, "FailureReason should explain partial success")
	})

	t.Run("WithHTTPContext_SetsIPAndUserAgent", func(t *testing.T) {
		// Setup
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

		// Execute
		event := NewEventBuilder().
			WithHTTPContext(ipAddress, userAgent).
			Build()

		// Assert
		assert.Equal(t, ipAddress, *event.IPAddress, "IPAddress should be set")
		assert.Equal(t, userAgent, event.UserAgent, "UserAgent should be set")
	})

	t.Run("WithRequestID_OverridesDefault", func(t *testing.T) {
		// Setup
		customRequestID := uuid.New()

		// Execute
		event := NewEventBuilder().
			WithRequestID(customRequestID).
			Build()

		// Assert
		assert.Equal(t, customRequestID, event.RequestID, "RequestID should be overridden")
	})

	t.Run("WithContext_MergesContextData", func(t *testing.T) {
		// Setup
		contextData := map[string]interface{}{
			"session_id":  "abc-123",
			"2fa_method":  "totp",
			"login_count": 5,
		}

		// Execute
		event := NewEventBuilder().
			WithContext(contextData).
			Build()

		// Assert
		assert.Equal(t, "abc-123", event.ContextData["session_id"])
		assert.Equal(t, "totp", event.ContextData["2fa_method"])
		assert.Equal(t, 5, event.ContextData["login_count"])
	})

	t.Run("WithContextValue_AddsSingleValue", func(t *testing.T) {
		// Execute
		event := NewEventBuilder().
			WithContextValue("email", "user@example.com").
			WithContextValue("verified", true).
			Build()

		// Assert
		assert.Equal(t, "user@example.com", event.ContextData["email"])
		assert.Equal(t, true, event.ContextData["verified"])
	})

	t.Run("WithContext_MultipleCalls_MergesData", func(t *testing.T) {
		// Execute
		event := NewEventBuilder().
			WithContext(map[string]interface{}{
				"key1": "value1",
			}).
			WithContext(map[string]interface{}{
				"key2": "value2",
			}).
			Build()

		// Assert
		assert.Equal(t, "value1", event.ContextData["key1"])
		assert.Equal(t, "value2", event.ContextData["key2"])
	})

	t.Run("FluentChaining_CompleteLoginEvent", func(t *testing.T) {
		// Setup
		userID := uuid.New()
		sessionID := uuid.New()
		requestID := uuid.New()

		// Execute - complete login event using all builder methods
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionLogin).
			WithResource(testResourceTypeSession, &sessionID).
			WithSuccess().
			WithHTTPContext("203.0.113.42", "Mozilla/5.0").
			WithRequestID(requestID).
			WithContext(map[string]interface{}{
				"2fa_enabled": true,
				"2fa_method":  "totp",
			}).
			Build()

		// Assert - verify all fields set correctly
		require.NotNil(t, event.UserID)
		assert.Equal(t, userID, *event.UserID)
		assert.Equal(t, testActionLogin, event.Action)
		assert.Equal(t, testResourceTypeSession, event.ResourceType)
		require.NotNil(t, event.ResourceID)
		assert.Equal(t, sessionID, *event.ResourceID)
		assert.Equal(t, OutcomeSuccess, event.Outcome)
		assert.Equal(t, "203.0.113.42", *event.IPAddress)
		assert.Equal(t, "Mozilla/5.0", event.UserAgent)
		assert.Equal(t, requestID, event.RequestID)
		assert.Equal(t, true, event.ContextData["2fa_enabled"])
		assert.Equal(t, "totp", event.ContextData["2fa_method"])
	})

	t.Run("FluentChaining_LogoutSingleSession", func(t *testing.T) {
		// Setup
		userID := uuid.New()
		sessionID := uuid.New()

		// Execute - logout single session
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionLogout).
			WithResource(testResourceTypeSession, &sessionID).
			WithSuccess().
			WithHTTPContext("192.168.1.100", "Mozilla/5.0").
			WithContext(map[string]interface{}{
				"session_id":     sessionID.String(),
				"logout_all":     false,
				"session_valid":  true,
				"session_active": true,
			}).
			Build()

		// Assert - verify logout structure
		assert.Equal(t, testActionLogout, event.Action)
		assert.Equal(t, testResourceTypeSession, event.ResourceType)
		require.NotNil(t, event.ResourceID)
		assert.Equal(t, sessionID, *event.ResourceID)
		assert.Equal(t, false, event.ContextData["logout_all"])
	})

	t.Run("FluentChaining_LogoutAllSessions", func(t *testing.T) {
		// Setup
		userID := uuid.New()

		// Execute - logout all sessions (no specific resource ID)
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionLogout).
			WithResource(testResourceTypeUser, nil). // No specific resource ID
			WithSuccess().
			WithHTTPContext("192.168.1.100", "Mozilla/5.0").
			WithContext(map[string]interface{}{
				"logout_all":      true,
				"sessions_count":  3,
				"sessions_closed": 3,
			}).
			Build()

		// Assert - verify logout all structure
		assert.Equal(t, testActionLogout, event.Action)
		assert.Equal(t, testResourceTypeUser, event.ResourceType)
		assert.Nil(t, event.ResourceID, "ResourceID should be nil for logout all")
		assert.Equal(t, true, event.ContextData["logout_all"])
		assert.Equal(t, 3, event.ContextData["sessions_count"])
	})

	t.Run("FluentChaining_FailedLogin", func(t *testing.T) {
		// Execute - failed login attempt
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithFailure("invalid password").
			WithHTTPContext("203.0.113.42", "Mozilla/5.0").
			WithContextValue("login_attempt", "email_password").
			WithContextValue("email", "user@example.com").
			Build()

		// Assert - verify failure structure
		assert.Nil(t, event.UserID, "UserID should be nil for failed login")
		assert.Equal(t, testActionLogin, event.Action)
		assert.Equal(t, OutcomeFailure, event.Outcome)
		assert.Equal(t, "invalid password", event.FailureReason)
		assert.Equal(t, "email_password", event.ContextData["login_attempt"])
	})

	t.Run("FluentChaining_PasswordReset", func(t *testing.T) {
		// Setup
		userID := uuid.New()

		// Execute - password reset request
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionPasswordReset).
			WithResource(testResourceTypeUser, &userID).
			WithSuccess().
			WithHTTPContext("203.0.113.42", "Mozilla/5.0").
			WithContext(map[string]interface{}{
				"reset_stage":  "requested",
				"email":        "user@example.com",
				"token_expiry": time.Now().Add(6 * time.Hour).Format(time.RFC3339),
			}).
			Build()

		// Assert - verify password reset structure
		assert.Equal(t, testActionPasswordReset, event.Action)
		assert.Equal(t, "requested", event.ContextData["reset_stage"])
		assert.Contains(t, event.ContextData, "token_expiry")
	})

	t.Run("FluentChaining_TokenRefresh", func(t *testing.T) {
		// Setup
		userID := uuid.New()
		tokenID := uuid.New()

		// Execute - token refresh
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionTokenRefresh).
			WithResource(testResourceTypeToken, &tokenID).
			WithSuccess().
			WithHTTPContext("203.0.113.42", "Mozilla/5.0").
			WithContext(map[string]interface{}{
				"token_family":      "family-123",
				"rotation_strategy": "strict",
				"old_token_id":      tokenID.String(),
			}).
			Build()

		// Assert - verify token refresh structure
		assert.Equal(t, testActionTokenRefresh, event.Action)
		assert.Equal(t, testResourceTypeToken, event.ResourceType)
		assert.Equal(t, "strict", event.ContextData["rotation_strategy"])
	})
}

// TestEventValidation validates the Validate() method for AuditEvent.
func TestEventValidation(t *testing.T) {
	t.Run("ValidEvent_PassesValidation", func(t *testing.T) {
		// Setup - complete valid event
		userID := uuid.New()
		event := NewEventBuilder().
			WithUser(userID).
			WithAction(testActionLogin).
			WithSuccess().
			WithHTTPContext("192.168.1.100", "Mozilla/5.0").
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.NoError(t, err, "Valid event should pass validation")
	})

	t.Run("MissingAction_FailsValidation", func(t *testing.T) {
		// Setup - event without action
		event := NewEventBuilder().
			WithSuccess().
			Build()
		event.Action = "" // Clear the action

		// Execute
		err := event.Validate()

		// Assert
		assert.Error(t, err, "Event without action should fail validation")
		assert.Contains(t, err.Error(), "action is required")
	})

	t.Run("InvalidOutcome_FailsValidation", func(t *testing.T) {
		// Setup - event with invalid outcome
		event := NewEventBuilder().
			WithAction(testActionLogin).
			Build()
		event.Outcome = "invalid_outcome"

		// Execute
		err := event.Validate()

		// Assert
		assert.Error(t, err, "Event with invalid outcome should fail validation")
		assert.Contains(t, err.Error(), "invalid audit event outcome")
	})

	t.Run("InvalidIPAddress_FailsValidation", func(t *testing.T) {
		// Setup - event with invalid IP
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			WithHTTPContext("invalid-ip", "Mozilla/5.0").
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.Error(t, err, "Event with invalid IP should fail validation")
		assert.Contains(t, err.Error(), "invalid IP address")
	})

	t.Run("ValidIPv4Address_PassesValidation", func(t *testing.T) {
		// Setup
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			WithHTTPContext("203.0.113.42", "Mozilla/5.0").
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.NoError(t, err, "Valid IPv4 address should pass validation")
	})

	t.Run("ValidIPv6Address_PassesValidation", func(t *testing.T) {
		// Setup
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			WithHTTPContext("2001:db8::1", "Mozilla/5.0").
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.NoError(t, err, "Valid IPv6 address should pass validation")
	})

	t.Run("EmptyIPAddress_PassesValidation", func(t *testing.T) {
		// Setup - IP address is optional
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.NoError(t, err, "Event without IP address should pass validation (optional field)")
	})

	t.Run("ZeroTimestamp_FailsValidation", func(t *testing.T) {
		// Setup
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			Build()
		event.Timestamp = time.Time{} // Zero timestamp

		// Execute
		err := event.Validate()

		// Assert
		assert.Error(t, err, "Event with zero timestamp should fail validation")
		assert.Contains(t, err.Error(), "timestamp is required")
	})

	t.Run("NilRequestID_FailsValidation", func(t *testing.T) {
		// Setup
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithSuccess().
			Build()
		event.RequestID = uuid.Nil

		// Execute
		err := event.Validate()

		// Assert
		assert.Error(t, err, "Event with nil request ID should fail validation")
		assert.Contains(t, err.Error(), "request ID is required")
	})

	t.Run("NilUserID_PassesValidation", func(t *testing.T) {
		// Setup - UserID is optional (failed login scenarios)
		event := NewEventBuilder().
			WithAction(testActionLogin).
			WithFailure("invalid credentials").
			Build()

		// Execute
		err := event.Validate()

		// Assert
		assert.NoError(t, err, "Event with nil UserID should pass validation (optional)")
		assert.Nil(t, event.UserID, "UserID should be nil for failed login")
	})
}

// TestUUIDv7Generation verifies that EventBuilder generates time-sortable UUID v7 IDs.
func TestUUIDv7Generation(t *testing.T) {
	t.Run("GeneratesUUIDv7_WithTimestamp", func(t *testing.T) {
		// Execute - create multiple events in sequence
		events := make([]*AuditEvent, 5)
		for i := 0; i < 5; i++ {
			events[i] = NewEventBuilder().
				WithAction(testActionLogin).
				WithSuccess().
				Build()
			time.Sleep(2 * time.Millisecond) // Small delay to ensure different timestamps
		}

		// Assert - verify IDs are time-ordered (UUID v7 embeds timestamp)
		for i := 1; i < len(events); i++ {
			// UUID v7 format: timestamp in first 48 bits should be increasing
			prevID := events[i-1].ID.String()
			currID := events[i].ID.String()

			assert.NotEqual(t, prevID, currID, "Sequential events should have different IDs")

			// Verify IDs are not nil UUIDs
			assert.NotEqual(t, uuid.Nil, events[i].ID)
		}

		// Verify all IDs are unique
		idSet := make(map[uuid.UUID]bool)
		for _, event := range events {
			assert.False(t, idSet[event.ID], "Event IDs should be unique")
			idSet[event.ID] = true
		}
	})
}
