// Package migrations embeds the SQL schema so every binary carries it and
// applies it at startup; there is no separate migration tool to deploy.
package migrations

import "embed"

// FS holds the numbered migration files (NNN_name.sql), applied in order.
//
//go:embed *.sql
var FS embed.FS
