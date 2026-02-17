package session

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chen3feng/stl4go"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sirupsen/logrus"
)

var clientDebugSessionPool = os.Getenv("CLIENT_DEBUG_SESSION_POOL") == "1"
var clientStreamCounter atomic.Uint64

const clientCreateStreamMaxAttempts = 3
const clientCreateSessionMaxProbeInflight = 2

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut  util.DialOutFunc
	settings util.StringMap

	sessionCounter atomic.Uint64

	idleSession     *stl4go.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]

	idleSessionTimeout time.Duration
	minIdleSession     int

	createFailureLock   sync.Mutex
	createFailureCount  int
	createNextAllowedAt time.Time
	createLastErr       error
	createProbeInflight int
}

func NewClient(ctx context.Context, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, settings util.StringMap,
) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		settings:           settings,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = stl4go.NewSkipList[uint64, *Session]()
	util.StartRoutine(c.die, idleSessionCheckInterval, c.idleCleanup)
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	for attempt := 1; attempt <= clientCreateStreamMaxAttempts; attempt++ {
		session = c.getIdleSession()
		if session == nil {
			session, err = c.createSessionWithBackoff(ctx)
			if session != nil && clientDebugSessionPool {
				logrus.Infoln("create session:", session.seq)
			}
			if session == nil {
				if err != nil && attempt < clientCreateStreamMaxAttempts && shouldRetryCreateStreamErr(err) {
					logrus.Warnf("[Client] create session transient failure, retrying (%d/%d): %v", attempt, clientCreateStreamMaxAttempts, err)
					continue
				}
				return nil, fmt.Errorf("failed to create session: %w", err)
			}
		} else {
			if clientDebugSessionPool {
				logrus.Infoln("get session:", session.seq)
			}
		}

		stream, err = session.OpenStream()
		if err != nil {
			session.Close()
			if attempt < clientCreateStreamMaxAttempts && shouldRetryCreateStreamErr(err) {
				logrus.Warnf("[Client] open stream transient failure, retrying (%d/%d): %v", attempt, clientCreateStreamMaxAttempts, err)
				continue
			}
			return nil, fmt.Errorf("failed to create stream: %w", err)
		}

		if clientDebugSessionPool {
			cn := clientStreamCounter.Add(1)
			s := c.sessionCounter.Load()
			logrus.Infoln("cumulative session:", s, "cumulative stream:", cn, "avg:", float64(cn)/float64(s))
		}

		stream.dieHook = func() {
			// If Session is not closed, put this Stream to pool
			if !session.IsClosed() {
				if clientDebugSessionPool {
					logrus.Infoln("put session:", session.seq, stream.id)
				}
				select {
				case <-c.die.Done():
					// Now client has been closed
					go session.Close()
				default:
					c.idleSessionLock.Lock()
					session.idleSince = time.Now()
					c.idleSession.Insert(math.MaxUint64-session.seq, session)
					c.idleSessionLock.Unlock()
				}
			} else {
				if clientDebugSessionPool {
					logrus.Infoln("discard session stream:", session.seq, stream.id)
				}
			}
		}

		return stream, nil
	}
	if err == nil {
		err = io.ErrClosedPipe
	}
	return nil, fmt.Errorf("failed to create session: %w", err)
}

func (c *Client) Warmup(ctx context.Context, count int) int {
	if c == nil || count <= 0 {
		return 0
	}
	warmed := 0
	for i := 0; i < count; i++ {
		select {
		case <-c.die.Done():
			return warmed
		default:
		}
		session, err := c.createSessionWithBackoff(ctx)
		if err != nil || session == nil {
			continue
		}
		c.idleSessionLock.Lock()
		session.idleSince = time.Now()
		c.idleSession.Insert(math.MaxUint64-session.seq, session)
		c.idleSessionLock.Unlock()
		warmed++
	}
	return warmed
}

func (c *Client) createSessionWithBackoff(ctx context.Context) (*Session, error) {
	for {
		releaseProbe, wait, lastErr := c.beginCreateAttempt()
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				if lastErr != nil {
					return nil, fmt.Errorf("%w (last upstream error: %v)", ctx.Err(), lastErr)
				}
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		}

		session, err := c.createSession(ctx)
		c.finishCreateAttempt(err)
		if releaseProbe != nil {
			releaseProbe()
		}
		if err != nil {
			return nil, err
		}
		return session, nil
	}
}

func (c *Client) beginCreateAttempt() (releaseProbe func(), wait time.Duration, lastErr error) {
	now := time.Now()
	c.createFailureLock.Lock()
	defer c.createFailureLock.Unlock()

	if c.createFailureCount <= 0 {
		return nil, 0, nil
	}
	lastErr = c.createLastErr
	if now.Before(c.createNextAllowedAt) {
		return nil, c.createNextAllowedAt.Sub(now), lastErr
	}
	if c.createProbeInflight >= clientCreateSessionMaxProbeInflight {
		return nil, 120 * time.Millisecond, lastErr
	}
	c.createProbeInflight++
	return func() {
		c.createFailureLock.Lock()
		if c.createProbeInflight > 0 {
			c.createProbeInflight--
		}
		c.createFailureLock.Unlock()
	}, 0, lastErr
}

func (c *Client) finishCreateAttempt(err error) {
	c.createFailureLock.Lock()
	defer c.createFailureLock.Unlock()

	if err == nil {
		c.createFailureCount = 0
		c.createNextAllowedAt = time.Time{}
		c.createLastErr = nil
		return
	}
	// Caller-side cancellations should not poison shared upstream health window.
	if errors.Is(err, context.Canceled) {
		return
	}

	c.createFailureCount++
	c.createLastErr = err
	cooldown := backoffDuration(c.createFailureCount)
	c.createNextAllowedAt = time.Now().Add(cooldown)
}

func backoffDuration(failureCount int) time.Duration {
	if failureCount <= 0 {
		return 0
	}
	backoff := 150 * time.Millisecond
	for i := 1; i < failureCount; i++ {
		backoff *= 2
		if backoff >= 2*time.Second {
			return 2 * time.Second
		}
	}
	if backoff > 2*time.Second {
		return 2 * time.Second
	}
	return backoff
}

func shouldRetryCreateStreamErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	if text == "" {
		return false
	}
	return strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "broken pipe") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "eof") ||
		strings.Contains(text, "context deadline exceeded") ||
		strings.Contains(text, "i/o timeout")
}

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	if !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		idle = it.Value()
		c.idleSession.Remove(it.Key())
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, &padding.DefaultPaddingFactory, c.settings)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		if clientDebugSessionPool {
			logrus.Infoln("session died:", session.seq, session.streamId.Load(), session.pktCounter.Load())
		}

		c.idleSessionLock.Lock()
		c.idleSession.Remove(math.MaxUint64 - session.seq)
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0
	var sessionToClose []*Session

	c.idleSessionLock.Lock()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if clientDebugSessionPool {
			logrus.Debugln("check session:", session.seq, expTime, session.idleSince)
		}

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		if clientDebugSessionPool {
			logrus.Infoln("local cleanup session:", session.seq)
		}
		session.Close()
	}
}
