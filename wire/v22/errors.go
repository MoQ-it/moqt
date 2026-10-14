package v22

import "fmt"

// SessionErrorCode terminates a whole session (Section 16.11.1).
type SessionErrorCode uint64

const (
	ErrNoError                 SessionErrorCode = 0x0
	ErrInternal                SessionErrorCode = 0x1
	ErrUnauthorized            SessionErrorCode = 0x2
	ErrProtocolViolation       SessionErrorCode = 0x3
	ErrInvalidRequestID        SessionErrorCode = 0x4
	ErrDuplicateTrackAlias     SessionErrorCode = 0x5
	ErrKeyValueFormatting      SessionErrorCode = 0x6
	ErrInvalidPath             SessionErrorCode = 0x8
	ErrMalformedPath           SessionErrorCode = 0x9
	ErrGoawayTimeout           SessionErrorCode = 0x10
	ErrControlMessageTimeout   SessionErrorCode = 0x11
	ErrDataStreamTimeout       SessionErrorCode = 0x12
	ErrAuthTokenCacheOverflow  SessionErrorCode = 0x13
	ErrDuplicateAuthTokenAlias SessionErrorCode = 0x14
	ErrMalformedAuthToken      SessionErrorCode = 0x16
	ErrUnknownAuthTokenAlias   SessionErrorCode = 0x17
	ErrExpiredAuthToken        SessionErrorCode = 0x18
	ErrInvalidAuthority        SessionErrorCode = 0x19
	ErrMalformedAuthority      SessionErrorCode = 0x1A
	ErrTooManyRequestUpdates   SessionErrorCode = 0x1B
)

// RequestErrorCode rejects a single request in REQUEST_ERROR (Section 16.11.2).
type RequestErrorCode uint64

const (
	ReqErrInternal             RequestErrorCode = 0x0
	ReqErrUnauthorized         RequestErrorCode = 0x1
	ReqErrTimeout              RequestErrorCode = 0x2
	ReqErrNotSupported         RequestErrorCode = 0x3
	ReqErrMalformedAuthToken   RequestErrorCode = 0x4
	ReqErrExpiredAuthToken     RequestErrorCode = 0x5
	ReqErrGoingAway            RequestErrorCode = 0x6
	ReqErrExcessiveLoad        RequestErrorCode = 0x9
	ReqErrDoesNotExist         RequestErrorCode = 0x10
	ReqErrInvalidRange         RequestErrorCode = 0x11
	ReqErrMalformedTrack       RequestErrorCode = 0x12
	ReqErrUninterested         RequestErrorCode = 0x20
	ReqErrPrefixOverlap        RequestErrorCode = 0x30
	ReqErrNamespaceTooLarge    RequestErrorCode = 0x31
	ReqErrUnsupportedExtension RequestErrorCode = 0x33
	ReqErrRedirect             RequestErrorCode = 0x34
	ReqErrConflictingFilters   RequestErrorCode = 0x35
	ReqErrInvalidFilter        RequestErrorCode = 0x36
)

// SessionError is a decoding or protocol failure that the spec says must
// close the session with Code.
type SessionError struct {
	Code   SessionErrorCode
	Reason string
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("moqt session error 0x%x: %s", uint64(e.Code), e.Reason)
}

func protocolViolation(format string, args ...any) error {
	return &SessionError{Code: ErrProtocolViolation, Reason: fmt.Sprintf(format, args...)}
}

func kvFormattingError(format string, args ...any) error {
	return &SessionError{Code: ErrKeyValueFormatting, Reason: fmt.Sprintf(format, args...)}
}

// StreamResetCode is used when resetting a stream or sending STOP_SENDING
// (Section 16.11.4).
type StreamResetCode uint64

const (
	ResetInternalError       StreamResetCode = 0x0
	ResetCancelled           StreamResetCode = 0x1
	ResetDeliveryTimeout     StreamResetCode = 0x2
	ResetSessionClosed       StreamResetCode = 0x3
	ResetGoingAway           StreamResetCode = 0x4
	ResetTooFarBehind        StreamResetCode = 0x5
	ResetUnknownObjectStatus StreamResetCode = 0x6
	ResetExpiredAuthToken    StreamResetCode = 0x7
	ResetExcessiveLoad       StreamResetCode = 0x9
	ResetMalformedTrack      StreamResetCode = 0x12
)
