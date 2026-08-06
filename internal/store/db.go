package store

import (
	"database/sql"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

// Store wraps an in-memory SQLite database. Nothing here is persisted to
// disk: the whole point of this tool is to be dropped into an environment,
// run, and leave no trace once the process exits.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serialize writes; modernc sqlite + in-memory can be touchy under concurrent writers
}

const schema = `
CREATE TABLE IF NOT EXISTS subnets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cidr TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT 'manual',
	iface TEXT NOT NULL DEFAULT '',
	discovered_at DATETIME NOT NULL,
	last_scan_at DATETIME,
	enabled INTEGER NOT NULL DEFAULT 1,
	hidden INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subnet_id INTEGER NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
	ip TEXT NOT NULL,
	mac TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	vendor TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'up',
	source TEXT NOT NULL DEFAULT 'auto',
	notes TEXT NOT NULL DEFAULT '',
	first_seen DATETIME NOT NULL,
	last_seen DATETIME NOT NULL,
	miss_count INTEGER NOT NULL DEFAULT 0,
	acknowledged INTEGER NOT NULL DEFAULT 0,
	UNIQUE(subnet_id, ip)
);

CREATE TABLE IF NOT EXISTS ports (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL DEFAULT 'tcp',
	state TEXT NOT NULL DEFAULT 'open',
	service TEXT NOT NULL DEFAULT '',
	banner TEXT NOT NULL DEFAULT '',
	product TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	first_seen DATETIME NOT NULL,
	last_seen DATETIME NOT NULL,
	is_new INTEGER NOT NULL DEFAULT 1,
	UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS tags (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	color TEXT NOT NULL DEFAULT '#888888'
);

CREATE TABLE IF NOT EXISTS host_tags (
	host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
	PRIMARY KEY (host_id, tag_id)
);

CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type TEXT NOT NULL,
	message TEXT NOT NULL,
	entity_id INTEGER NOT NULL DEFAULT 0,
	timestamp DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS auth (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	username TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	password_salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	port INTEGER NOT NULL DEFAULT 0,
	service TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT 'warning',
	label TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	version_below TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hosts_subnet ON hosts(subnet_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
`

// Open creates the SQLite database the tool runs on. With an empty path it's
// a private in-memory database (the default): nothing touches disk and
// everything is gone the moment the process exits, consistent with the
// "leave no trace" design goal. With a non-empty path, it opens (creating if
// needed) a database file at that path instead, so data survives a restart —
// opt-in via the -db-file flag for the cases where that's actually wanted.
//
// A named in-memory DSN with cache=shared lets multiple connections in the
// pool see the same database (a plain ":memory:" DSN gives every connection
// its own empty database, which breaks database/sql's pooling).
//
// initialPassword, if non-empty, seeds the admin account with that password
// on first run instead of the built-in default (DefaultPassword) — it's
// ignored on subsequent runs against an already-seeded database.
func Open(path, initialPassword string) (*Store, error) {
	dsn := "file:enumerator?mode=memory&cache=shared"
	if path != "" {
		dsn = "file:" + path
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // avoid sqlite "database is locked" errors entirely
	// SQLite enforces "ON DELETE CASCADE" only when foreign key support is
	// turned on for the connection — it's off by default. Without this,
	// deleting a subnet silently orphans its hosts/ports/tags instead of
	// cascading, which both leaks rows and left orphaned host nodes with no
	// subnet to link to in the topology graph (they'd all collapse onto the
	// same origin point).
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// CREATE TABLE IF NOT EXISTS doesn't add new columns to a table that
	// already exists from an older version of this schema (relevant with
	// -db-file, where the database persists across upgrades). Errors here
	// are expected and ignored once the column already exists.
	_, _ = db.Exec(`ALTER TABLE subnets ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE ports ADD COLUMN product TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE ports ADD COLUMN version TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE risk_rules ADD COLUMN version_below TEXT NOT NULL DEFAULT ''`)
	st := &Store{db: db}
	if err := st.ensureDefaultAuth(initialPassword); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed default auth: %w", err)
	}
	if err := st.ensureDefaultRiskRules(); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed default risk rules: %w", err)
	}
	return st, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
