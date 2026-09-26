# Tools

Tokenis gives the model up to eight tools. Each one answers a narrow kind of
question about the dataset, and every call goes through admission control
before anything leaves the gateway. This page covers what each tool answers,
what it returns, and why a question can be refused.

Tool schemas are generated from the loaded dataset. Column arguments are
enums of the real column names, and filter values for open columns are enums
of the values present (up to `max_enum_values`). A malformed call is rejected
by schema validation before it reaches the gateway. Run
`tokenis-mcp tools --demo --format mcp` to see the exact schemas.

Some tools appear only when the dataset supports them:

| Tool | Offered when |
|---|---|
| `compare_periods` | The schema has at least two sealed columns |
| `similarity_search` | `[data] embedding_column` is set (with an `entity` token column) |
| `disclose_ratio`, `disclose_bucket` | At least one `[[reveal.purposes]]` is configured |

## Filters

Most tools take a `filters` object. Its keys are the filterable columns
(`open` and `token`), and a record matches when it has **all** the given
values. There is no OR, no negation and no range. Open-column values must be
written exactly as `describe_dataset` lists them. Token-column values are
32-character hex tokens taken from earlier results. Leaving `filters` out
means every record, which D1 refuses for any value-bearing aggregate (see
below).

## The tools

### `describe_dataset`

Call this first. It takes no arguments and uses no budget.

The result has `records` (the record count), `min_query_set_size` (*k*),
`columns` (name, protection, description, unit; the values of each open
column, or `distinct_values` when there are more than `max_enum_values`; the
operations and result mode of each sealed column), `budget` (`remaining`,
`window`, `window_key`), `reveal_purposes` (the purposes this caller may
use), `tools`, and `notice` when the operator set one (the demo does).

### `aggregate`

| Argument | Type | Values |
|---|---|---|
| `function` | string, required | `sum`, `avg`, `count`; `var` only if some sealed column has `allow_variance` |
| `column` | string | A sealed column; not needed for `count` |
| `filters` | object | See [Filters](#filters) |

Returns `function`, `column`, `filters`, `value`, `matched_records`, and
`unit` when the column has one (`unit^2` for `var`). A column with
`result_mode = "band"` returns a 1-2-5 band such as `"[2,000, 5,000)"`
instead of the exact value.

Can be refused by D1, D2 (`sum`, `avg`, `var`), D3, D4 (tainted callers get
`count` only) and D5. A `var` on a column without `allow_variance` is an
argument error.

### `group_by`

| Argument | Type | Values |
|---|---|---|
| `key` | string, required | A filterable column whose values define the groups |
| `function` | string | `sum` (default), `avg`, `count` |
| `column` | string | A sealed column; not needed for `count` |
| `filters` | object | Applied to every group; may not include `key` |

Returns `key`, `function`, `filters`, `column` (unless counting) and
`groups`. Each group is `{"group", "suppressed": false, "value",
"matched_records"}`, or `{"group", "suppressed": true}` when the policy
refused that group for any reason. The call itself is not an error when some
groups are suppressed.

Each group is admitted separately, so each admitted group uses one unit of
budget. If `key` has more distinct values than `max_groups` (default 50) the
call is an argument error; filters do not change this count, so group by a
coarser column instead.

### `compare_periods`

| Argument | Type | Values |
|---|---|---|
| `column_a` | string, required | Sealed column used as the baseline |
| `column_b` | string, required | Sealed column compared against it; must differ, same `scale` |
| `filters` | object | See [Filters](#filters) |

Returns `from`, `to`, `filters`, `direction` (`increase`, `decrease`, or
`flat` when the totals are within 2% of the baseline) and `ratio_band`, one
of `<0.5x`, `0.5-0.8x`, `0.8-0.95x`, `0.95-1.05x`, `1.05-1.2x`, `1.2-2x`,
`>=2x` (null when the baseline total is not positive or the other is
negative). The totals themselves never leave.

It runs two admitted sums, one per column, so it uses two units of budget
and can be refused by anything that refuses a `sum`.

### `similarity_search`

| Argument | Type | Values |
|---|---|---|
| `token` | string, required | An entity token (`^[0-9a-f]{32}$`) from an earlier result |
| `top_k` | integer | 1 to `max_top_k` (default limit 5); default 3 |

Returns `token` and `results`, a list of `{"token", "similarity"}` where
similarity is `low`, `medium`, `high` or `very high`. Tokens can come from a
`group_by` on the entity column (suppressed groups still carry their token)
or from earlier `similarity_search` results.

It has no filter, so D1, D2 and D5 do not apply, but it uses budget (D3, or
the tainted budget and call cap under D4). An unknown token is refused, and
still uses budget.

### `exists`

| Argument | Type | Values |
|---|---|---|
| `filters` | object, required | At least one non-null filter |

Returns `filters`, `at_least_k_records` and `k`. It answers `false` for
fewer than *k* matches, including zero, so it never tells 0 from a handful.
When D1 would refuse the set, `exists` answers instead of refusing and uses
no budget. Otherwise it can be refused by D3 or D4.

### `disclose_ratio` (audited disclosure)

| Argument | Type | Values |
|---|---|---|
| `column` | string, required | Sealed column to total |
| `numerator_filters` | object, required | Numerator group |
| `denominator_filters` | object, required | Denominator group |
| `purpose` | string, required | A configured purpose name |

Returns `column`, both filter objects and `ratio` (rounded to 6 decimals).
Both totals are admitted like `aggregate` sums, so this uses two units of
budget. Refused if the caller is not listed in the purpose's `principals`,
if either sum is refused, or if the denominator total is zero. Every
attempt is written to the audit trail as a reveal or a denial.

### `disclose_bucket` (audited disclosure)

| Argument | Type | Values |
|---|---|---|
| `column` | string, required | Sealed column to total |
| `thresholds` | number list, required | 1 to `max_buckets - 1` values, strictly increasing, in the column's units |
| `labels` | string list, required | One more than `thresholds`, each 1-64 characters |
| `purpose` | string, required | A configured purpose name |
| `filters` | object | See [Filters](#filters) |

Returns `column`, `filters` and `bucket`: the first label whose threshold the
total is below, or the last label if the total is at or above every
threshold. One admitted sum, so one unit of budget; refused like
`disclose_ratio`.

## Why a question is refused

Every refusal returns the same message, whatever the reason:

```text
Denied by the disclosure policy. The request may match too few records,
combine with earlier queries to isolate individual records, exceed your
query budget, or need a purpose you are not authorised for. Try broader
filters or a different question; the gateway does not say which reason
applied.
```

The rule that fired goes only to the audit trail (the denial entry's
`detail`) and, for a refused call, the operator's log
(`denied tool=... rule=...` at INFO). A
precise reason would itself leak something: "matched 2 records" is a count,
and naming the rule is a one-bit oracle. Argument errors are different: they
start with `invalid arguments:` and are specific, because they depend only
on the public schema.

Checks run in this order: the tainted call cap, D5, the tainted surface, D1,
the budget, then D2.

**D1: query-set size.** An aggregate must match at least *k* records
(`min_query_set_size`, default 5) and at most *n - k*, where *n* is the
total record count. The upper bound stops the complement trick: the total
over everyone minus the total over all but a few gives those few. This is
why an unfiltered `aggregate` over every record is always refused. Any
filter value held by fewer than *k* records can never pass.

**D2: differencing audit.** Each `sum`, `avg` and `var` (including those
inside `group_by`, `compare_periods` and the disclosure tools) is checked
against the queries already admitted on that column. The gateway keeps a
row-reduced basis of their record sets and refuses a query if, combined with
them, it would pin down a single record. With `cell_aware = true` (the
default) it also refuses when it would pin down any group of fewer than *k*
records. `sum` and `avg` share one history per column; `var` has its own.
Counts are not audited, since a count is a public set size. The history is
shared by all callers and is not reset by the budget window, so a question
can be refused because of someone else's earlier question.

**D3: budget.** Each principal may have `budget` admitted queries (default
200) per `window` (`day`, `hour` in UTC, or `total`). Refused calls do not
use budget. `describe_dataset` shows what remains.

**D4: tainted context.** When the host marks the caller's context as holding
untrusted content (see [llm-integration.md](llm-integration.md) and
`taint_header` in [configuration.md](configuration.md)):

| Rule | Effect |
|---|---|
| `D4-surface` | Only counts and lookups are admitted: `aggregate` with `count`, `group_by` with `count`, `exists`, and `similarity_search`. Sums, averages, variances, `compare_periods` and the disclosure tools are refused |
| `D4-Btau` | Admitted calls use a separate, smaller budget, `taint_budget` (default 20) |
| `D4-Ctau` | Every call counts against `taint_call_cap` (default 50), admitted or not |
| `D4-external-effect` | Tools with an external effect are refused while tainted. None of the eight tools has one, so this rule does not fire today |

**D5: catalogue.** Deny by default: a value-bearing aggregate may only name a
column in the catalogue of configured sealed columns. Through MCP or
`tokenis.llm`, schema validation rejects unknown column names first, so D5
is a backstop.

Other refusals recorded under their own names: an aggregate outside the
decryption range (`decryption-range`, see
[troubleshooting.md](troubleshooting.md)), an unknown similarity token
(`unknown-token`), a zero denominator (`zero-denominator`) and a purpose the
caller is not authorised for.

### Worked example: a differencing pair

Take *k* = 5 and 40 `tech` records, 38 of them in `region = "Seoul"`.

```json
{"function": "sum", "column": "revenue", "filters": {"industry": "tech"}}
```

This matches 40 records and is admitted.

```json
{"function": "sum", "column": "revenue", "filters": {"industry": "tech", "region": "Seoul"}}
```

This matches 38 records, so D1 passes. But subtracting it from the first
answer gives the total of the 2 `tech` records outside Seoul, fewer than *k*.
D2 refuses it, and the same query as an `avg` is refused too. The order
matters: had the second query come first, the first would be refused. A
`count` of the same filters is still admitted.

### Getting an answer

- **Broaden the filters.** Drop a condition, or filter on a value many
  records share. Filters that differ from an earlier one by only a few
  records are the ones D2 refuses.
- **Ask for the breakdown up front.** One `group_by` returns every group
  that is safe to show and marks the rest suppressed, instead of a series of
  narrow `aggregate` calls. Decide the finest breakdown you need before
  asking for totals it could be subtracted from.
- **Ask for less precision.** `compare_periods` gives a direction and a
  ratio band. `exists` answers "at least *k*" without a number. An operator
  can set `result_mode = "band"` on a sealed column, and `disclose_bucket`
  places a total in named ranges for an authorised purpose.
- **Do not retry near-identical queries.** Every admitted query uses budget,
  and small variations are exactly what D2 is built to catch.

The threat model behind these rules is in [../SECURITY.md](../SECURITY.md).
