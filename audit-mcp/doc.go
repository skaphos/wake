// SPDX-License-Identifier: MIT

// Command wake-audit-mcp is the module root for Wake's repository policy-audit
// services: FileTree sources (local checkout, remote GitHub) that feed the
// pure core/audit engine, plus an MCP-over-stdio server (internal/mcpserver,
// internal/app) exposing the audit_repository and audit_org tools.
package main
