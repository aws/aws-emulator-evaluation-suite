"""get-deleted-lookup-table-fails."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deleted-lookup-table-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLookupTable on a table ARN that was already deleted returns
    ResourceNotFoundException, not a stale/empty success response."""
    logs = ctx.client("logs")

    name = _lookup_table_name(ctx)
    create_resp = logs.create_lookup_table(
        lookupTableName=name,
        tableBody="id,label\n1,a\n2,b\n",
        tags={"sim2real": CHECK},
    )
    arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete_lookup_table(logs, arn))

    # Sanity: retrievable before deletion.
    logs.get_lookup_table(lookupTableArn=arn)

    logs.delete_lookup_table(lookupTableArn=arn)

    def _gone() -> bool:
        try:
            logs.get_lookup_table(lookupTableArn=arn)
        except ClientError:
            return True
        return False

    assert _poll_until(_gone, timeout_s=30, interval_s=3), (
        "GetLookupTable still served a deleted lookup table after 30s"
    )
    code, message = _error(lambda: logs.get_lookup_table(lookupTableArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetLookupTable on a deleted table, got {code!r}"
    )
    expected_message = f"Lookup table '{name}' not found in account '{ctx.account}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
