"""list-lookup-tables-reflects-create-and-delete."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-lookup-tables-reflects-create-and-delete"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLookupTables (the ListLookupTables surface) reflects a newly created lookup table
    immediately and excludes it immediately after deletion, staying consistent with GetLookupTable."""
    logs = ctx.client("logs")

    name = _sanitize_lookup_name(ctx.unique_name("sim2reallookup"))
    table_body = "code,label\n1,one\n2,two\n3,three\n"

    def _describe_all() -> list[dict[str, Any]]:
        tables: list[dict[str, Any]] = []
        token = None
        while True:
            kwargs = {"lookupTableNamePrefix": name}
            if token:
                kwargs["nextToken"] = token
            try:
                resp = logs.describe_lookup_tables(**kwargs)
            except Exception as exc:
                from botocore.exceptions import ClientError

                # AWS raises ResourceNotFoundException (rather than an empty page) when no
                # lookup tables in the account match the prefix -- treat that as "no tables".
                if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return tables
                raise
            tables.extend(resp.get("lookupTables", []))
            token = resp.get("nextToken")
            if not token:
                break
        return tables

    def _present(arn: str) -> bool:
        return any(t["lookupTableArn"] == arn for t in _describe_all())

    resp = logs.create_lookup_table(
        lookupTableName=name,
        tableBody=table_body,
        description="sim2real check",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    arn = resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete_lookup_table(logs, arn))

    listed = _poll_until(lambda: _present(arn), timeout_s=30.0, interval_s=2.0)
    assert listed, "newly created lookup table did not appear in DescribeLookupTables"

    get_resp = logs.get_lookup_table(lookupTableArn=arn)
    assert get_resp["lookupTableName"] == name, (
        f"GetLookupTable name mismatch: expected {name!r}, got {get_resp.get('lookupTableName')!r}"
    )

    logs.delete_lookup_table(lookupTableArn=arn)

    absent = _poll_until(lambda: not _present(arn), timeout_s=30.0, interval_s=2.0)
    assert absent, "deleted lookup table still appeared in DescribeLookupTables"

    code, code_msg = _error_code(lambda: logs.get_lookup_table(lookupTableArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetLookupTable on a deleted table to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"Lookup table '{name}' not found in account '{ctx.account}'"
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"


def _sanitize_lookup_name(raw: str) -> str:
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return cleaned or "sim2reallookup"


def _safe_delete_lookup_table(logs, arn: str) -> None:
    try:
        logs.delete_lookup_table(lookupTableArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(predicate: Callable[[], bool], timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
