"""search-tables-name-predicate-tokenises-on-punctuation-not-substring."""
# SearchTables' Name predicate splits the table name on punctuation and exact-match compares each
# token against Value, so `aa-<tok>` and `bb-<tok>-cc` match Value=<tok> but `dd<tok>ee` does not
# (SearchTablesRequest.Filters: "if Key=Name and Value=link, tables named customer-link and
# xx-link-yy are returned, but xxlinkyy is not returned"). Only `-`, which the documented example
# uses, is relied on. The search index is eventually consistent with CreateTable, so reads are
# polled. A 12-hex-character token cannot collide with another table name in the account, so the
# result is exactly the two matching tables. `Comparator` is omitted for a string Key, and a
# filter that matches nothing returns an empty TableList rather than an error.
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-tables-name-predicate-tokenises-on-punctuation-not-substring"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchTables' Name predicate matches whole punctuation-delimited tokens, not substrings."""
    glue = ctx.client("glue")

    # A 12-hex-char token: a single tokeniser token (no punctuation inside it) that cannot
    # already exist in this account's catalog, so the expected result set is exactly the two
    # tables this check creates with the token as a standalone name token.
    token = ctx.unique_name("zz").lower()

    database = ctx.unique_name("sim2real_behav_srchdb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    # `hyphen_tail` and `hyphen_middle` carry `token` as a whole token; `glued` contains it
    # only as a substring of a longer token. That difference is the entire subject.
    hyphen_tail = f"aa-{token}"
    hyphen_middle = f"bb-{token}-cc"
    glued = f"dd{token}ee"
    for name in (hyphen_tail, hyphen_middle, glued):
        glue.create_table(
            DatabaseName=database,
            TableInput={
                "Name": name,
                "StorageDescriptor": {
                    "Columns": [{"Name": "payload", "Type": "string"}],
                    "Location": f"s3://example-bucket/{name}/",
                },
                "Parameters": {"sim2real": CHECK},
            },
        )
        ctx.on_cleanup(lambda n=name: _retry_delete(
            lambda: glue.delete_table(DatabaseName=database, Name=n),
            f"glue table {database}.{n}"))

    # All three tables genuinely exist, read back through a different operation than the one
    # that created them. Without this, a target that silently failed to create `glued`
    # would pass the exclusion assertion below for the wrong reason.
    for name in (hyphen_tail, hyphen_middle, glued):
        table = glue.get_table(DatabaseName=database, Name=name)["Table"]
        assert table["Name"] == name, (
            f"GetTable({database}.{name}) returned Name={table.get('Name')!r}; the three "
            f"tables the search must discriminate between are not all present"
        )

    expected = {hyphen_tail, hyphen_middle}

    # SearchTables is served from an index that lags CreateTable, so poll until BOTH matching
    # tables are visible. The poll RAISES on timeout: a target with no search index at all
    # must fail here rather than sail through the exclusion assertion on an empty result.
    def _search(value: str) -> set[str]:
        found: set[str] = set()
        token_page = None
        for _ in range(20):
            kwargs = {
                "Filters": [{"Key": "Name", "Value": value}],
                "MaxResults": 100,
            }
            if token_page is not None:
                kwargs["NextToken"] = token_page
            resp = glue.search_tables(**kwargs)
            found.update(t["Name"] for t in resp["TableList"])
            token_page = resp.get("NextToken")
            if not token_page:
                return found
        raise AssertionError(
            f"SearchTables(Name={value!r}) paged past 20 pages / {len(found)} tables; a "
            f"predicate on a 12-hex-char token can match at most the 2 tables this check "
            f"created, so the filter is being ignored server-side"
        )

    matched = _poll_until(
        lambda: _search(token),
        lambda names: expected <= names,
        timeout_s=240.0,
        interval_s=5.0,
        reason=(f"SearchTables' index is eventually consistent with CreateTable; waiting for "
                f"{sorted(expected)} to become searchable under Name={token!r}"),
    )

    # The discriminating assertion, taken from the SAME response as the positive result, so
    # absence is bounded by demonstrated presence rather than by a wait: a target doing
    # naive substring matching returns `glued` too; one doing whole-name equality returns
    # nothing and never leaves the poll above.
    assert glued not in matched, (
        f"SearchTables(Name={token!r}) returned {glued!r}, which contains the token only as "
        f"a substring of the single token {glued!r}; the documented tokeniser splits on '-' "
        f"and exact-matches each token, so only {sorted(expected)} may match. Got "
        f"{sorted(matched)}"
    )
    assert matched == expected, (
        f"SearchTables(Name={token!r}) must return exactly {sorted(expected)} — no table "
        f"predating this check can contain a fresh 12-hex token — but returned "
        f"{sorted(matched)}"
    )

    # A predicate that matches nothing must filter everything out, not fall back to listing
    # the catalog. This is the control that separates "the filter works" from "the filter is
    # applied but happens to be permissive".
    absent = _search(token + "x")
    assert not absent & {hyphen_tail, hyphen_middle, glued}, (
        f"SearchTables(Name={token + 'x'!r}) returned "
        f"{sorted(absent & {hyphen_tail, hyphen_middle, glued})}; no token in those names "
        f"equals {token + 'x'!r}, so the predicate is not being evaluated"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s ({reason}); "
                f"last value={last!r}"
            )
        time.sleep(interval_s)


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "ResourceNotFoundException")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
