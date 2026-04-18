module github.com/skaphos/wake-cli

go 1.26.2

require (
	github.com/skaphos/wake-core v0.0.0-00010101000000-000000000000
	github.com/skaphos/wake-events-mcp v0.0.0-00010101000000-000000000000
	github.com/skaphos/wake-forensics-mcp v0.0.0-00010101000000-000000000000
)

replace github.com/skaphos/wake-core => ../wake-core

replace github.com/skaphos/wake-forensics-mcp => ../wake-forensics-mcp

replace github.com/skaphos/wake-events-mcp => ../wake-events-mcp
