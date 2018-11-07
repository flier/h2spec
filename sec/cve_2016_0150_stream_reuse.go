package sec

import (
	"fmt"

	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
)

func StreamReuse() *spec.TestGroup {
	tg := NewTestGroup("CVE-2016-0150", "Stream Reuse")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends two requests with same stream ID",
		Requirement: "HTTP/2 stream represents one request-response cycle and once closed.",
		Run: func(c *config.Config, conn *spec.Conn) (err error) {
			if err = conn.Handshake(); err != nil {
				return
			}

			headers := spec.CommonHeaders(c)

			hp := http2.HeadersFrameParam{
				StreamID:      5,
				EndStream:     true,
				EndHeaders:    true,
				BlockFragment: conn.EncodeHeaders(headers),
			}
			if err = conn.WriteHeaders(hp); err != nil {
				return
			}
			if err = conn.WriteHeaders(hp); err != nil {
				return
			}

			return verifyStreamCloseOrGoAway(conn, http2.ErrCodeStreamClosed, 5)
		},
	})

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends multi requests which mixed same stream ID",
		Requirement: "HTTP/2 stream represents one request-response cycle and once closed.",
		Run: func(c *config.Config, conn *spec.Conn) error {
			err := conn.Handshake()
			if err != nil {
				return err
			}

			headers := spec.CommonHeaders(c)

			for j := 0; j < 2; j++ {
				for i := 0; i < 5; i++ {
					hp := http2.HeadersFrameParam{
						StreamID:      uint32(i*2 + 1),
						EndStream:     true,
						EndHeaders:    true,
						BlockFragment: conn.EncodeHeaders(headers),
					}
					conn.WriteHeaders(hp)
				}
			}

			return verifyStreamCloseOrGoAway(conn, http2.ErrCodeStreamClosed, 1, 3, 5, 7, 9)
		},
	})

	return tg
}

func verifyStreamCloseOrGoAway(conn *spec.Conn, errCode http2.ErrCode, streamIDs ...uint32) error {
	var actual spec.Event

	passed := false
	for !conn.Closed {
		event := conn.WaitEvent()

		switch ev := event.(type) {
		case spec.ConnectionClosedEvent:
			passed = true
		case spec.HeadersFrameEvent:
			if ev.StreamEnded() {
				streamIDs = verifyStreamClosed(streamIDs, ev.StreamID)
				passed = len(streamIDs) == 0
			}
		case spec.DataFrameEvent:
			if ev.StreamEnded() {
				streamIDs = verifyStreamClosed(streamIDs, ev.StreamID)
				passed = len(streamIDs) == 0
			}
		case spec.GoAwayFrameEvent:
			passed = ev.ErrCode == errCode
			actual = ev
		case spec.TimeoutEvent:
			if actual == nil {
				actual = ev
			}
		}

		if passed || actual != nil {
			break
		}
	}

	if !passed {
		return &spec.TestError{
			Expected: []string{
				fmt.Sprintf("no more open stream: %v", streamIDs),
				fmt.Sprintf(spec.ExpectedGoAwayFrame, errCode),
				spec.ExpectedConnectionClosed,
			},
			Actual: actual.String(),
		}
	}

	return nil
}

func verifyStreamClosed(streamIDs []uint32, streamID uint32) []uint32 {
	for i, id := range streamIDs {
		if id == streamID {
			return append(streamIDs[:i], streamIDs[i+1:]...)
		}
	}

	return streamIDs
}
