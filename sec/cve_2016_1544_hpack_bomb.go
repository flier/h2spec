package sec

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func HPACKBomb() *spec.TestGroup {
	tg := NewTestGroup("CVE-2016-1544", "HPACK Bomb")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends request with HPACK bomb",
		Requirement: "HTTP/2 stream represents request-response cycles and once closed.",
		Run: func(c *config.Config, conn *spec.Conn) (err error) {
			if err = conn.Handshake(); err != nil {
				return
			}

			streamID := uint32(1)
			requests := c.Requests
			streams := make(map[uint32]int)

			contentLength := spec.HeaderField("content-length", "5")
			bomb := spec.HeaderField("bomb", strings.Repeat("A", 3910))
			headers := append(spec.CommonHeaders(c), contentLength, bomb)

			var buf bytes.Buffer
			encoder := hpack.NewEncoder(&buf)

			for _, header := range headers {
				encoder.WriteField(header)
			}

			hp := http2.HeadersFrameParam{
				StreamID:      streamID,
				EndStream:     true,
				EndHeaders:    true,
				BlockFragment: buf.Bytes(),
			}

			if err = conn.WriteHeaders(hp); err != nil {
				return
			}

			streams[streamID] = 0

			maxConcurrentStreams := int(conn.Settings[http2.SettingMaxConcurrentStreams])

			if maxConcurrentStreams > requests {
				maxConcurrentStreams = requests
			}

			buf.Reset()

			for _, header := range headers {
				if err = encoder.WriteField(header); err != nil {
					return
				}
			}

			for buf.Len() < c.MaxHeaderLen {
				if err = encoder.WriteField(bomb); err != nil {
					return
				}
			}

			requests--

			for i := 1; requests >= 0 && i < maxConcurrentStreams; i++ {
				streamID += 2

				hp = http2.HeadersFrameParam{
					StreamID:      streamID,
					EndStream:     true,
					EndHeaders:    true,
					BlockFragment: buf.Bytes(),
				}

				if err = conn.WriteHeaders(hp); err != nil {
					// server may force close the connection
					return nil
				}

				streams[streamID] = 0

				requests--
			}

			for !conn.Closed {
				event := conn.WaitEvent()

				switch actual := event.(type) {
				case spec.ConnectionClosedEvent:
					break
				case spec.RSTStreamFrameEvent:
					delete(streams, actual.StreamID)
				case spec.HeadersFrameEvent:
					continue
				case spec.DataFrameEvent:
					if actual.StreamEnded() {
						delete(streams, actual.StreamID)
					}
				case spec.GoAwayFrameEvent:
					conn.Close()

					if actual.ErrCode != http2.ErrCodeProtocol {
						return &spec.TestError{
							Expected: []string{
								spec.ExpectedConnectionClosed,
								fmt.Sprintf(spec.ExpectedGoAwayFrame, http2.ErrCodeProtocol),
							},
							Actual: actual.String(),
						}
					}

					break
				default:
					return &spec.TestError{
						Expected: []string{
							spec.ExpectedConnectionClosed,
							fmt.Sprintf(spec.ExpectedGoAwayFrame, http2.ErrCodeProtocol),
						},
						Actual: actual.String(),
					}
				}

				if len(streams) == 0 {
					conn.Close()
					break
				}
			}

			return
		},
	})

	return tg
}
