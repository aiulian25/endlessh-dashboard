package store

// Country identity is query-time only: source labels remain untouched. A
// two-letter ASCII code wins; uncoded/invalid-code names are separate fallbacks.
// SQLite lower() folds ASCII case; non-ASCII spelling is preserved, not guessed
// into a country code. Empty identities remain NULL and are not known countries.
const countryWhitespaceSQL = `char(9)||char(10)||char(11)||char(12)||char(13)||' '`
const countryNameSQL = `TRIM(country, ` + countryWhitespaceSQL + `)`
const countryCodeTrimSQL = `TRIM(country_code, ` + countryWhitespaceSQL + `)`
const countryCodeSQL = `CASE WHEN UPPER(` + countryCodeTrimSQL + `) GLOB '[A-Z][A-Z]' THEN UPPER(` + countryCodeTrimSQL + `) ELSE '' END`
const countryKeySQL = `CASE WHEN (` + countryCodeSQL + `)<>'' THEN 'code:'||(` + countryCodeSQL + `) WHEN ` + countryNameSQL + `<>'' THEN 'name:'||LOWER(` + countryNameSQL + `) END`
const countryDisplaySQL = `COALESCE(MIN(NULLIF(` + countryNameSQL + `,'')),MIN(NULLIF((` + countryCodeSQL + `),'')),'')`
