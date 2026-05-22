package ingest

import "context"

// contextKey is an unexported type used for context keys to prevent collisions.
type contextKey string

const (
	// AccountIDKey is the context key for the AWS account ID.
	AccountIDKey contextKey = "account_id"
)

// WithAccountID returns a new context with the account ID attached.
func WithAccountID(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, AccountIDKey, accountID)
}

// AccountIDFromContext retrieves the account ID from the context.
// Returns empty string if not set.
func AccountIDFromContext(ctx context.Context) string {
	accountID, ok := ctx.Value(AccountIDKey).(string)
	if !ok {
		return ""
	}
	return accountID
}
