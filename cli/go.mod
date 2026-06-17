module github.com/skaphos/wake-cli

go 1.26.2

require (
	github.com/atotto/clipboard v0.1.4
	github.com/cli/go-gh/v2 v2.13.0
	github.com/cli/oauth v1.2.2
	github.com/modelcontextprotocol/go-sdk v1.6.1
	github.com/skaphos/wake-core v0.0.0-00010101000000-000000000000
	github.com/skaphos/wake-events-mcp v0.0.0-00010101000000-000000000000
	github.com/skaphos/wake-forensics-mcp v0.0.0-00010101000000-000000000000
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/cli/safeexec v1.0.0 // indirect
	github.com/cli/shurcooL-graphql v0.0.4 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/go-github/v82 v82.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/henvic/httpretty v0.0.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/thlib/go-timezone-local v0.0.0-20210907160436-ef149e42d28e // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/term v0.30.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/skaphos/wake-core => ../core

replace github.com/skaphos/wake-forensics-mcp => ../forensics-mcp

replace github.com/skaphos/wake-events-mcp => ../events-mcp
