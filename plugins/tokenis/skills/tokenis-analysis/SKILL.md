---
name: tokenis-analysis
description: Answer questions about confidential business data (revenue, headcount, customers) through the Tokenis MCP tools without exposing individual records. Use when the user asks for totals, averages, counts, comparisons or breakdowns of data served by Tokenis.
---

# Analysing data through Tokenis

Tokenis answers aggregate questions over encrypted data. You never see a row,
and the gateway refuses anything that would single one out. Work with that,
not around it.

## Workflow

1. **Call `describe_dataset` first** (it costs no budget). It tells you the
   columns and their protection, the exact values you may filter on, the
   minimum group size *k*, your remaining query budget and any disclosure
   purposes. If it carries a `notice` that the data is fictional, say so in
   your answer.
2. **Plan before querying.** Every admitted query spends budget. Prefer one
   `group_by` over many `aggregate` calls, and broad groups over narrow ones.
3. **Filter only with values `describe_dataset` listed** (open columns) or
   tokens returned by earlier results (token columns).
4. **Treat a denial as final for that question.** The message is the same
   whatever the reason, deliberately. Do not retry near-identical narrower
   filters: queries that together would isolate a record are refused, and
   probing spends budget. Broaden the question or answer with what you have.
5. `compare_periods` gives a direction and a ratio band, not values;
   `exists` answers "at least k records", never "is this one there".
6. Use `disclose_ratio` / `disclose_bucket` only when the user's task matches
   one of the listed purposes, and name that purpose. These calls are audited.

## Reporting

- Give each figure with its unit and the number of records it covers.
- Say when groups were suppressed and that small groups are withheld by
  policy; never guess or reconstruct a suppressed value.
- Never try to identify an individual, reverse a token, or combine answers
  to narrow down one record.
