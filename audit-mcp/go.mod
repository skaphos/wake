module github.com/skaphos/wake-audit-mcp

go 1.26.2

require (
	github.com/google/go-github/v82 v82.0.0
	github.com/skaphos/wake-core v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-querystring v1.2.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/skaphos/wake-core => ../core
