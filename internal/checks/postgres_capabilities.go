package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const postgresCapabilitiesQueryTimeout = 5 * time.Second

// postgresRelationCapabilities descreve uma relação exatamente como ela existe
// no servidor monitorado. A descoberta usa os catálogos, não o número da versão.
type postgresRelationCapabilities struct {
	qualifiedName string
	columns       map[string]struct{}
}

func (c postgresRelationCapabilities) available() bool {
	return c.qualifiedName != ""
}

func (c postgresRelationCapabilities) hasColumn(name string) bool {
	_, ok := c.columns[name]
	return ok
}

// O separador não aparece nos nomes das colunas mantidas pelas extensões
// oficiais. Ele evita depender de JSON/arrays, cujos codecs mudam entre drivers.
const postgresCapabilityColumnSeparator = "\x1f"

const sqlPostgresExtensionRelationCapabilities = `WITH extension_relation AS (
  SELECT c.oid,
         quote_ident(n.nspname) || '.' || quote_ident(c.relname) AS qualified_name
    FROM pg_extension e
    JOIN pg_namespace n ON n.oid = e.extnamespace
    JOIN pg_class c ON c.relnamespace = n.oid
    JOIN pg_depend dep ON dep.refclassid = 'pg_extension'::regclass
                      AND dep.refobjid = e.oid
                      AND dep.classid = 'pg_class'::regclass
                      AND dep.objid = c.oid
                      AND dep.deptype = 'e'
   WHERE e.extname = $1
     AND c.relname = $2
   LIMIT 1
)
SELECT COALESCE(max(r.qualified_name), ''),
       COALESCE(string_agg(
         CASE WHEN a.attnum > 0 AND NOT a.attisdropped THEN a.attname END,
         E'\x1f' ORDER BY a.attnum
       ), '')
  FROM extension_relation r
  LEFT JOIN pg_attribute a ON a.attrelid = r.oid`

func discoverPostgresExtensionRelationCapabilities(
	ctx context.Context,
	pool pgxPool,
	extensionName string,
	relationName string,
) (postgresRelationCapabilities, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCapabilitiesQueryTimeout)
	defer cancel()

	var qualifiedName, rawColumns string
	if err := pool.QueryRow(
		qctx,
		sqlPostgresExtensionRelationCapabilities,
		extensionName,
		relationName,
	).Scan(&qualifiedName, &rawColumns); err != nil {
		return postgresRelationCapabilities{}, fmt.Errorf(
			"descoberta de capacidades de %s: %w",
			relationName,
			err,
		)
	}

	capabilities := postgresRelationCapabilities{
		qualifiedName: strings.TrimSpace(qualifiedName),
		columns:       make(map[string]struct{}),
	}
	for _, column := range strings.Split(rawColumns, postgresCapabilityColumnSeparator) {
		column = strings.TrimSpace(column)
		if column != "" {
			capabilities.columns[column] = struct{}{}
		}
	}
	return capabilities, nil
}
