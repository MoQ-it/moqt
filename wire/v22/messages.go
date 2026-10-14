package v22

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MessageType identifies a control message (Section 9, Table 5).
type MessageType uint64

const (
	MsgRequestUpdate      MessageType = 0x2
	MsgSubscribe          MessageType = 0x3
	MsgSubscribeOK        MessageType = 0x4
	MsgRequestError       MessageType = 0x5
	MsgPublishNamespace   MessageType = 0x6
	MsgRequestOK          MessageType = 0x7
	MsgNamespace          MessageType = 0x8
	MsgPublishDone        MessageType = 0xB
	MsgTrackStatus        MessageType = 0xD
	MsgNamespaceDone      MessageType = 0xE
	MsgPublishSkipped     MessageType = 0xF
	MsgGoaway             MessageType = 0x10
	MsgFetch              MessageType = 0x16
	MsgFetchOK            MessageType = 0x18
	MsgPublish            MessageType = 0x1D
	MsgPublishStateNotify MessageType = 0x22
	MsgSubscribeNamespace MessageType = 0x50
	MsgSubscribeTracks    MessageType = 0x51
	MsgSetup              MessageType = 0x2F00
)

// IsRequest reports whether t may open a bidirectional request stream
// (Section 6.3).
func (t MessageType) IsRequest() bool {
	switch t {
	case MsgTrackStatus, MsgSubscribe, MsgPublish, MsgFetch, MsgPublishNamespace,
		MsgSubscribeNamespace, MsgSubscribeTracks:
		return true
	}
	return false
}

// Message is a control message.
type Message interface {
	Type() MessageType
	appendBody(b []byte) ([]byte, error)
	decodeBody(d *Decoder)
}

// MaxMessageBody is the largest body the 16-bit length can express.
const MaxMessageBody = 1<<16 - 1

// MaxGoawayURI bounds the New Session URI and Redirect Connect URI.
const MaxGoawayURI = 8192

// AppendMessage appends m with its type and 16-bit length.
func AppendMessage(b []byte, m Message) ([]byte, error) {
	b = AppendVarint(b, uint64(m.Type()))
	lenAt := len(b)
	b = append(b, 0, 0)
	b, err := m.appendBody(b)
	if err != nil {
		return nil, fmt.Errorf("encoding 0x%x: %w", uint64(m.Type()), err)
	}
	n := len(b) - lenAt - 2
	if n > MaxMessageBody {
		return nil, fmt.Errorf("message 0x%x body is %d bytes, over the 16-bit limit", uint64(m.Type()), n)
	}
	binary.BigEndian.PutUint16(b[lenAt:], uint16(n))
	return b, nil
}

// StreamReader is what ReadMessage needs from a stream; *bufio.Reader
// satisfies it.
type StreamReader interface {
	io.Reader
	io.ByteReader
}

// ReadMessage reads one control message. It returns io.EOF only on a clean
// end of stream between messages.
func ReadMessage(r StreamReader) (Message, error) {
	typ, err := ReadVarint(r)
	if err != nil {
		return nil, err
	}
	return ReadMessageBody(r, MessageType(typ))
}

// ReadMessageBody reads the length and body of a message whose type has
// already been read, as on a control stream where the SETUP type doubles
// as the stream type.
func ReadMessageBody(r StreamReader, typ MessageType) (Message, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, unexpectedEOF(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, unexpectedEOF(err)
	}
	return ParseMessage(typ, body)
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// ParseMessage decodes a message body. A body that is shorter or longer
// than the message needs is a protocol violation (Section 9).
func ParseMessage(t MessageType, body []byte) (Message, error) {
	m := newMessage(t)
	if m == nil {
		return nil, protocolViolation("unknown message type 0x%x", uint64(t))
	}
	d := NewDecoder(body)
	m.decodeBody(d)
	if err := d.Err(); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, protocolViolation("message 0x%x body too short", uint64(t))
		}
		return nil, err
	}
	if d.Len() > 0 {
		return nil, protocolViolation("message 0x%x has %d trailing bytes", uint64(t), d.Len())
	}
	return m, nil
}

func newMessage(t MessageType) Message {
	switch t {
	case MsgSetup:
		return &Setup{}
	case MsgGoaway:
		return &Goaway{}
	case MsgRequestOK:
		return &RequestOK{}
	case MsgRequestError:
		return &RequestError{}
	case MsgRequestUpdate:
		return &RequestUpdate{}
	case MsgSubscribe:
		return &Subscribe{}
	case MsgSubscribeOK:
		return &SubscribeOK{}
	case MsgPublish:
		return &Publish{}
	case MsgPublishDone:
		return &PublishDone{}
	case MsgPublishStateNotify:
		return &PublishStateNotify{}
	case MsgFetch:
		return &Fetch{}
	case MsgFetchOK:
		return &FetchOK{}
	case MsgTrackStatus:
		return &TrackStatus{}
	case MsgPublishNamespace:
		return &PublishNamespace{}
	case MsgSubscribeNamespace:
		return &SubscribeNamespace{}
	case MsgSubscribeTracks:
		return &SubscribeTracks{}
	case MsgNamespace:
		return &NamespaceMsg{}
	case MsgNamespaceDone:
		return &NamespaceDone{}
	case MsgPublishSkipped:
		return &PublishSkipped{}
	}
	return nil
}

func (d *Decoder) checkedParams(allowed []ParamType, msg string) *Params {
	p := d.Params()
	if d.err == nil {
		if err := p.check(allowed, msg); err != nil {
			d.fail(err)
		}
	}
	return p
}

func appendCheckedParams(b []byte, p *Params, allowed []ParamType, msg string) ([]byte, error) {
	if p != nil {
		if err := p.check(allowed, msg); err != nil {
			return nil, err
		}
	}
	return appendParams(b, p)
}

// Setup option types (Section 9.1, Table 11).
const (
	OptPath                  = 0x01
	OptAuthorizationToken    = 0x03
	OptMaxAuthTokenCacheSize = 0x04
	OptAuthority             = 0x05
	OptMaxFilterRanges       = 0x06
	OptMOQTImplementation    = 0x07
	OptMaxRequestUpdates     = 0x08
)

// Setup is the first message on each control stream (Section 9.1). Options
// are kept as raw Key-Value-Pairs because unknown options must be ignored.
type Setup struct {
	Options KeyValues
}

func (*Setup) Type() MessageType                     { return MsgSetup }
func (m *Setup) appendBody(b []byte) ([]byte, error) { return m.Options.Append(b), nil }
func (m *Setup) decodeBody(d *Decoder)               { m.Options = d.KeyValues() }

// Goaway announces that the sender will close the session or request
// soon (Section 9.2).
type Goaway struct {
	NewSessionURI string
	Timeout       uint64 // ms
}

func (*Goaway) Type() MessageType { return MsgGoaway }
func (m *Goaway) appendBody(b []byte) ([]byte, error) {
	if len(m.NewSessionURI) > MaxGoawayURI {
		return nil, errors.New("GOAWAY URI too long")
	}
	return AppendVarint(appendLengthPrefixed(b, []byte(m.NewSessionURI)), m.Timeout), nil
}
func (m *Goaway) decodeBody(d *Decoder) {
	m.NewSessionURI = string(d.LengthPrefixed(MaxGoawayURI, "GOAWAY URI"))
	m.Timeout = d.Varint()
}

// RequestOK answers PUBLISH, REQUEST_UPDATE, TRACK_STATUS,
// SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS and PUBLISH_NAMESPACE (Section 9.3).
type RequestOK struct {
	Params          *Params
	TrackProperties KeyValues
}

func (*RequestOK) Type() MessageType { return MsgRequestOK }
func (m *RequestOK) appendBody(b []byte) ([]byte, error) {
	b, err := appendCheckedParams(b, m.Params, requestOKParams, "REQUEST_OK")
	if err != nil {
		return nil, err
	}
	return m.TrackProperties.Append(b), nil
}
func (m *RequestOK) decodeBody(d *Decoder) {
	m.Params = d.checkedParams(requestOKParams, "REQUEST_OK")
	m.TrackProperties = d.KeyValues()
}

// Redirect tells the requester to retry elsewhere (Section 9.4.1).
type Redirect struct {
	ConnectURI string
	Track      FullTrackName
}

// RequestError rejects a request (Section 9.4).
type RequestError struct {
	Code RequestErrorCode
	// RetryInterval is the minimum retry delay in ms plus one; 0 means do
	// not retry.
	RetryInterval uint64
	Reason        string
	Redirect      *Redirect // only with ReqErrRedirect
}

func (*RequestError) Type() MessageType { return MsgRequestError }
func (m *RequestError) appendBody(b []byte) ([]byte, error) {
	b = AppendVarint(AppendVarint(b, uint64(m.Code)), m.RetryInterval)
	b = AppendReasonPhrase(b, m.Reason)
	if (m.Code == ReqErrRedirect) != (m.Redirect != nil) {
		return nil, errors.New("REQUEST_ERROR needs a Redirect exactly when the code is REDIRECT")
	}
	if m.Redirect != nil {
		b = appendLengthPrefixed(b, []byte(m.Redirect.ConnectURI))
		b = m.Redirect.Track.Append(b)
	}
	return b, nil
}
func (m *RequestError) decodeBody(d *Decoder) {
	m.Code = RequestErrorCode(d.Varint())
	m.RetryInterval = d.Varint()
	m.Reason = d.ReasonPhrase()
	if m.Code == ReqErrRedirect {
		m.Redirect = &Redirect{ConnectURI: string(d.LengthPrefixed(MaxGoawayURI, "redirect URI"))}
		m.Redirect.Track = d.FullTrackName()
	}
}

// RequestUpdate modifies an existing request (Section 9.5).
type RequestUpdate struct {
	RequestID uint64
	Params    *Params
}

func (*RequestUpdate) Type() MessageType { return MsgRequestUpdate }
func (m *RequestUpdate) appendBody(b []byte) ([]byte, error) {
	return appendCheckedParams(AppendVarint(b, m.RequestID), m.Params, requestUpdateParams, "REQUEST_UPDATE")
}
func (m *RequestUpdate) decodeBody(d *Decoder) {
	m.RequestID = d.Varint()
	m.Params = d.checkedParams(requestUpdateParams, "REQUEST_UPDATE")
}

// Subscribe starts a subscription (Section 9.6).
type Subscribe struct {
	RequestID uint64
	Track     FullTrackName
	Params    *Params
}

func (*Subscribe) Type() MessageType { return MsgSubscribe }
func (m *Subscribe) appendBody(b []byte) ([]byte, error) {
	return appendCheckedParams(m.Track.Append(AppendVarint(b, m.RequestID)), m.Params, subscribeParams, "SUBSCRIBE")
}
func (m *Subscribe) decodeBody(d *Decoder) {
	m.RequestID = d.Varint()
	m.Track = d.FullTrackName()
	m.Params = d.checkedParams(subscribeParams, "SUBSCRIBE")
}

// SubscribeOK accepts a subscription (Section 9.7).
type SubscribeOK struct {
	TrackAlias      uint64
	Params          *Params
	TrackProperties KeyValues
}

func (*SubscribeOK) Type() MessageType { return MsgSubscribeOK }
func (m *SubscribeOK) appendBody(b []byte) ([]byte, error) {
	b, err := appendCheckedParams(AppendVarint(b, m.TrackAlias), m.Params, subscribeOKParams, "SUBSCRIBE_OK")
	if err != nil {
		return nil, err
	}
	return m.TrackProperties.Append(b), nil
}
func (m *SubscribeOK) decodeBody(d *Decoder) {
	m.TrackAlias = d.Varint()
	m.Params = d.checkedParams(subscribeOKParams, "SUBSCRIBE_OK")
	m.TrackProperties = d.KeyValues()
}

// Publish starts a publisher-initiated subscription (Section 9.8).
type Publish struct {
	RequestID       uint64
	Track           FullTrackName
	TrackAlias      uint64
	Params          *Params
	TrackProperties KeyValues
}

func (*Publish) Type() MessageType { return MsgPublish }
func (m *Publish) appendBody(b []byte) ([]byte, error) {
	b = AppendVarint(m.Track.Append(AppendVarint(b, m.RequestID)), m.TrackAlias)
	b, err := appendCheckedParams(b, m.Params, publishParams, "PUBLISH")
	if err != nil {
		return nil, err
	}
	return m.TrackProperties.Append(b), nil
}
func (m *Publish) decodeBody(d *Decoder) {
	m.RequestID = d.Varint()
	m.Track = d.FullTrackName()
	m.TrackAlias = d.Varint()
	m.Params = d.checkedParams(publishParams, "PUBLISH")
	m.TrackProperties = d.KeyValues()
}

// PublishDoneCode is the status in PUBLISH_DONE (Section 16.11.3).
type PublishDoneCode uint64

const (
	DoneInternalError  PublishDoneCode = 0x0
	DoneUnauthorized   PublishDoneCode = 0x1
	DoneTrackEnded     PublishDoneCode = 0x2
	DoneGoingAway      PublishDoneCode = 0x4
	DoneTooFarBehind   PublishDoneCode = 0x5
	DoneExpired        PublishDoneCode = 0x6
	DoneUpdateFailed   PublishDoneCode = 0x8
	DoneExcessiveLoad  PublishDoneCode = 0x9
	DoneMalformedTrack PublishDoneCode = 0x12
)

// StreamCountUnknown is the Stream Count a publisher sends when it cannot
// give the exact number.
const StreamCountUnknown = MaxVarint

// PublishDone ends a subscription (Section 9.9).
type PublishDone struct {
	StatusCode  PublishDoneCode
	StreamCount uint64
	Reason      string
}

func (*PublishDone) Type() MessageType { return MsgPublishDone }
func (m *PublishDone) appendBody(b []byte) ([]byte, error) {
	return AppendReasonPhrase(AppendVarint(AppendVarint(b, uint64(m.StatusCode)), m.StreamCount), m.Reason), nil
}
func (m *PublishDone) decodeBody(d *Decoder) {
	m.StatusCode = PublishDoneCode(d.Varint())
	m.StreamCount = d.Varint()
	m.Reason = d.ReasonPhrase()
}

// PublishStateNotify reports a publisher-side subscription change
// (Section 9.10).
type PublishStateNotify struct {
	Params *Params
}

func (*PublishStateNotify) Type() MessageType { return MsgPublishStateNotify }
func (m *PublishStateNotify) appendBody(b []byte) ([]byte, error) {
	return appendCheckedParams(b, m.Params, publishStateNotifyParams, "PUBLISH_STATE_NOTIFY")
}
func (m *PublishStateNotify) decodeBody(d *Decoder) {
	m.Params = d.checkedParams(publishStateNotifyParams, "PUBLISH_STATE_NOTIFY")
}

// Fetch requests already-published Objects (Section 9.11).
type Fetch struct {
	RequestID uint64
	Track     FullTrackName
	Params    *Params
}

func (*Fetch) Type() MessageType { return MsgFetch }
func (m *Fetch) appendBody(b []byte) ([]byte, error) {
	return appendCheckedParams(m.Track.Append(AppendVarint(b, m.RequestID)), m.Params, fetchParams, "FETCH")
}
func (m *Fetch) decodeBody(d *Decoder) {
	m.RequestID = d.Varint()
	m.Track = d.FullTrackName()
	m.Params = d.checkedParams(fetchParams, "FETCH")
}

// FetchOK accepts a fetch (Section 9.12).
type FetchOK struct {
	EndOfTrack      bool
	EndLocation     Location
	Params          *Params
	TrackProperties KeyValues
}

func (*FetchOK) Type() MessageType { return MsgFetchOK }
func (m *FetchOK) appendBody(b []byte) ([]byte, error) {
	var eot byte
	if m.EndOfTrack {
		eot = 1
	}
	b, err := appendCheckedParams(m.EndLocation.Append(append(b, eot)), m.Params, fetchOKParams, "FETCH_OK")
	if err != nil {
		return nil, err
	}
	return m.TrackProperties.Append(b), nil
}
func (m *FetchOK) decodeBody(d *Decoder) {
	switch eot := d.Byte(); eot {
	case 0, 1:
		m.EndOfTrack = eot == 1
	default:
		d.fail(protocolViolation("FETCH_OK End Of Track %d", eot))
	}
	m.EndLocation = d.Location()
	m.Params = d.checkedParams(fetchOKParams, "FETCH_OK")
	m.TrackProperties = d.KeyValues()
}

// TrackStatus asks for a track's status without subscribing (Section 9.13).
type TrackStatus struct {
	RequestID uint64
	Track     FullTrackName
	Params    *Params
}

func (*TrackStatus) Type() MessageType { return MsgTrackStatus }
func (m *TrackStatus) appendBody(b []byte) ([]byte, error) {
	return appendCheckedParams(m.Track.Append(AppendVarint(b, m.RequestID)), m.Params, trackStatusParams, "TRACK_STATUS")
}
func (m *TrackStatus) decodeBody(d *Decoder) {
	m.RequestID = d.Varint()
	m.Track = d.FullTrackName()
	m.Params = d.checkedParams(trackStatusParams, "TRACK_STATUS")
}

// prefixRequest is the shared body of PUBLISH_NAMESPACE,
// SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS.
type prefixRequest struct {
	RequestID uint64
	Prefix    Namespace
	Params    *Params
}

func (m *prefixRequest) append(b []byte, allowed []ParamType, name string) ([]byte, error) {
	return appendCheckedParams(m.Prefix.Append(AppendVarint(b, m.RequestID)), m.Params, allowed, name)
}
func (m *prefixRequest) decode(d *Decoder, allowed []ParamType, name string) {
	m.RequestID = d.Varint()
	m.Prefix = d.Namespace()
	m.Params = d.checkedParams(allowed, name)
}

// PublishNamespace advertises tracks under a namespace prefix (Section 9.14).
type PublishNamespace prefixRequest

func (*PublishNamespace) Type() MessageType { return MsgPublishNamespace }
func (m *PublishNamespace) appendBody(b []byte) ([]byte, error) {
	return (*prefixRequest)(m).append(b, namespaceRequestParams, "PUBLISH_NAMESPACE")
}
func (m *PublishNamespace) decodeBody(d *Decoder) {
	(*prefixRequest)(m).decode(d, namespaceRequestParams, "PUBLISH_NAMESPACE")
}

// SubscribeNamespace asks for namespaces under a prefix (Section 9.15).
type SubscribeNamespace prefixRequest

func (*SubscribeNamespace) Type() MessageType { return MsgSubscribeNamespace }
func (m *SubscribeNamespace) appendBody(b []byte) ([]byte, error) {
	return (*prefixRequest)(m).append(b, namespaceRequestParams, "SUBSCRIBE_NAMESPACE")
}
func (m *SubscribeNamespace) decodeBody(d *Decoder) {
	(*prefixRequest)(m).decode(d, namespaceRequestParams, "SUBSCRIBE_NAMESPACE")
}

// SubscribeTracks asks for a PUBLISH for every track under a prefix
// (Section 9.18).
type SubscribeTracks prefixRequest

func (*SubscribeTracks) Type() MessageType { return MsgSubscribeTracks }
func (m *SubscribeTracks) appendBody(b []byte) ([]byte, error) {
	return (*prefixRequest)(m).append(b, subscribeTracksParams, "SUBSCRIBE_TRACKS")
}
func (m *SubscribeTracks) decodeBody(d *Decoder) {
	(*prefixRequest)(m).decode(d, subscribeTracksParams, "SUBSCRIBE_TRACKS")
}

// NamespaceMsg announces a namespace on a SUBSCRIBE_NAMESPACE response
// stream (Section 9.16). Suffix is relative to the subscribed prefix.
type NamespaceMsg struct {
	Suffix Namespace
}

func (*NamespaceMsg) Type() MessageType                     { return MsgNamespace }
func (m *NamespaceMsg) appendBody(b []byte) ([]byte, error) { return m.Suffix.Append(b), nil }
func (m *NamespaceMsg) decodeBody(d *Decoder)               { m.Suffix = d.Namespace() }

// NamespaceDone withdraws a namespace (Section 9.17). Suffix is relative to
// the subscribed prefix, as for NAMESPACE.
type NamespaceDone struct {
	Suffix Namespace
}

func (*NamespaceDone) Type() MessageType                     { return MsgNamespaceDone }
func (m *NamespaceDone) appendBody(b []byte) ([]byte, error) { return m.Suffix.Append(b), nil }
func (m *NamespaceDone) decodeBody(d *Decoder)               { m.Suffix = d.Namespace() }

// PublishSkipped says a matching track will not get a PUBLISH
// (Section 9.19).
type PublishSkipped struct {
	Suffix    Namespace
	TrackName string
}

func (*PublishSkipped) Type() MessageType { return MsgPublishSkipped }
func (m *PublishSkipped) appendBody(b []byte) ([]byte, error) {
	return appendLengthPrefixed(m.Suffix.Append(b), []byte(m.TrackName)), nil
}
func (m *PublishSkipped) decodeBody(d *Decoder) {
	m.Suffix = d.Namespace()
	m.TrackName = string(d.LengthPrefixed(MaxFullTrackNameBytes, "track name"))
}
