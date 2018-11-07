package sec

import (
	"fmt"
	"math/rand"

	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
)

func DependencyCycle() *spec.TestGroup {
	tg := NewTestGroup("CVE-2015-8659", "Dependency Cycle")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends requests with Dependency Cycle",
		Requirement: "The endpoint MUST terminate the connection with a connection error.",
		Run: func(c *config.Config, conn *spec.Conn) (err error) {
			if err = conn.Handshake(); err != nil {
				return
			}

			var streamIDs []uint32
			streams := make(map[uint32]int)
			headers := spec.CommonHeaders(c)
			maxConcurrentStreams := int(conn.Settings[http2.SettingMaxConcurrentStreams])
			if maxConcurrentStreams == 0 {
				maxConcurrentStreams = c.Concurrency
			}
			if maxConcurrentStreams == 0 {
				maxConcurrentStreams = defaultMaxConcurrentStreams
			}

			for i := 0; i < maxConcurrentStreams; i++ {
				streamID := uint32(i*2 + 1)

				hp := http2.HeadersFrameParam{
					StreamID:      streamID,
					EndStream:     false,
					EndHeaders:    true,
					BlockFragment: conn.EncodeHeaders(headers),
				}

				if err = conn.WriteHeaders(hp); err != nil {
					return
				}

				streams[streamID] = 0
				streamIDs = append(streamIDs, streamID)
			}

			rand.Shuffle(len(streamIDs), func(i, j int) {
				streamIDs[i], streamIDs[j] = streamIDs[j], streamIDs[i]
			})

			for i := 0; i < maxConcurrentStreams; i++ {
				streamID := uint32(i*2 + 1)

				pp := http2.PriorityParam{
					StreamDep: streamIDs[i],
					Exclusive: true,
					Weight:    2,
				}

				if err = conn.WritePriority(streamID, pp); err != nil {
					return
				}
			}

			for i := 0; i < maxConcurrentStreams; i++ {
				streamID := uint32((maxConcurrentStreams-i)*2 - 1)

				if err = conn.WriteData(streamID, true, []byte("test")); err != nil {
					return
				}
			}

			for !conn.Closed {
				switch actual := conn.WaitEvent().(type) {
				case spec.WindowUpdateFrameEvent:
					// ignore
				case spec.HeadersFrameEvent:
					// ignore
				case spec.DataFrameEvent:
					if actual.StreamEnded() {
						delete(streams, actual.StreamID)

						if len(streams) == 0 {
							conn.Close()
							return nil
						}
					} else {
						streams[actual.StreamID] += len(actual.Data())
					}
				default:
					return &spec.TestError{
						Expected: []string{
							fmt.Sprintf("no more open stream: %v", streams),
							spec.ExpectedStreamClosed,
						},
						Actual: actual.String(),
					}
				}
			}

			return nil
		},
	})
	return tg
}
