"""lookup-table-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lookup-table-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLookupTable, GetLookupTable, DescribeLookupTables, UpdateLookupTable and
    DeleteLookupTable move a lookup table through create/active/update/delete consistently,
    including a full-replacement semantics check on UpdateLookupTable."""
    logs = ctx.client("logs")

    name = _lookup_table_name(ctx)
    csv_v1 = "id,label\n1,alpha\n2,beta\n"
    create_resp = logs.create_lookup_table(
        lookupTableName=name,
        tableBody=csv_v1,
        description="initial version",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete_lookup_table(logs, arn))

    got = logs.get_lookup_table(lookupTableArn=arn)
    assert got["lookupTableName"] == name, f"expected lookupTableName {name!r}, got {got['lookupTableName']!r}"
    assert got["description"] == "initial version", (
        f"expected description 'initial version', got {got['description']!r}"
    )
    assert got["tableBody"] == csv_v1, "GetLookupTable did not return the exact CSV that was uploaded"

    def _in_describe() -> bool:
        # DescribeLookupTables raises ResourceNotFoundException (rather than
        # returning an empty list) when no lookup table matches the given
        # prefix, e.g. immediately after creation before it is visible yet.
        try:
            resp = logs.describe_lookup_tables(lookupTableNamePrefix=name)
        except Exception as exc:  # noqa: BLE001
            if _error_code_of(exc) == "ResourceNotFoundException":
                return False
            raise
        return any(t["lookupTableArn"] == arn for t in resp.get("lookupTables", []))

    assert _poll_until(_in_describe, timeout_s=30, interval_s=3), (
        "lookup table not visible via DescribeLookupTables(lookupTableNamePrefix=...)"
    )

    # UpdateLookupTable is documented as a full-replacement operation.
    csv_v2 = "id,label\n1,alpha-updated\n2,beta-updated\n3,gamma\n"
    update_resp = logs.update_lookup_table(
        lookupTableArn=arn, tableBody=csv_v2, description="updated version"
    )
    assert update_resp["lookupTableArn"] == arn, (
        f"expected UpdateLookupTable to echo arn {arn!r}, got {update_resp['lookupTableArn']!r}"
    )

    got2 = logs.get_lookup_table(lookupTableArn=arn)
    assert got2["tableBody"] == csv_v2, "UpdateLookupTable did not fully replace the table content"
    assert got2["description"] == "updated version", (
        f"expected description 'updated version', got {got2['description']!r}"
    )
    assert got2["tableBody"] != csv_v1, "stale (pre-update) content still served after UpdateLookupTable"

    logs.delete_lookup_table(lookupTableArn=arn)

    def _gone_from_get() -> bool:
        return _error_code(lambda: logs.get_lookup_table(lookupTableArn=arn)) == "ResourceNotFoundException"

    assert _poll_until(_gone_from_get, timeout_s=30, interval_s=3), (
        "GetLookupTable still succeeded after DeleteLookupTable"
    )

    def _gone_from_describe() -> bool:
        # DescribeLookupTables raises ResourceNotFoundException (rather than
        # returning an empty list) once no lookup table matches the prefix,
        # which is exactly the "gone" condition we're polling for here.
        try:
            resp = logs.describe_lookup_tables(lookupTableNamePrefix=name)
        except Exception as exc:  # noqa: BLE001
            if _error_code_of(exc) == "ResourceNotFoundException":
                return True
            raise
        return all(t["lookupTableArn"] != arn for t in resp.get("lookupTables", []))

    assert _poll_until(_gone_from_describe, timeout_s=30, interval_s=3), (
        "deleted lookup table still listed via DescribeLookupTables"
    )


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
        return None
    except Exception as exc:  # noqa: BLE001
        return _error_code_of(exc)


def _error_code_of(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return type(exc).__name__


def _lookup_table_name(ctx: Any) -> str:
    # lookupTableName pattern is ^[a-zA-Z0-9_]+$ -- ctx.unique_name emits hyphens, so sanitize.
    return ctx.unique_name("sim2real_lookup_").replace("-", "_")


def _safe_delete_lookup_table(logs: Any, arn: str) -> None:
    try:
        logs.delete_lookup_table(lookupTableArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
