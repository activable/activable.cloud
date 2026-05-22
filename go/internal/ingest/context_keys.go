package ingest

import "context"

// contextKey is an unexported type for context key constants.
// Using an unexported type prevents collisions with keys defined in other packages.
type contextKey string

// AccountIDKey is the context key for storing the AWS account ID.
const AccountIDKey contextKey = "account_id"

// WithAccountID returns a new context with the account ID attached.
func WithAccountID(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, AccountIDKey, accountID)
}

// AccountIDFromContext retrieves the account ID from the context.
// Returns an empty string if no account ID is set.
func AccountIDFromContext(ctx context.Context) string {
	accountID, ok := ctx.Value(AccountIDKey).(string)
	if !ok {
		return ""
	}
	return accountID
}
