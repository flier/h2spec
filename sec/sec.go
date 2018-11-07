package sec

import "github.com/summerwind/h2spec/spec"

var key = "sec"

func NewTestGroup(section string, name string) *spec.TestGroup {
	return &spec.TestGroup{
		Key:     key,
		Section: section,
		Name:    name,
	}
}

func Spec() *spec.TestGroup {
	tg := &spec.TestGroup{
		Key:  key,
		Name: "Security tests for HTTP/2 server",
	}

	tg.AddTestGroup(DependencyCycle())
	tg.AddTestGroup(StreamReuse())
	tg.AddTestGroup(HPACKBomb())
	tg.AddTestGroup(SlowRead())

	return tg
}
