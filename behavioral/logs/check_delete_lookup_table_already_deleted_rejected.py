"""delete-lookup-table-already-deleted-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-lookup-table-already-deleted-rejected"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a lookup table a second time is rejected with ResourceNotFoundException; the first
    delete's effect (the table is gone) is unchanged, and a fresh create+delete elsewhere still
    succeeds cleanly (positive control)."""
    logs = ctx.client("logs")
    table_body = "code,label\n1,one\n"

    name = _sanitize_lookup_name(ctx.unique_name("sim2realneglookup"))
    arn = logs.create_lookup_table(
        lookupTableName=name, tableBody=table_body,
        tags={"sim2real": "delete-lookup-table-already-deleted-rejected"},
    )["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete(logs, arn))

    # First delete succeeds (this is itself a positive control for DeleteLookupTable).
    logs.delete_lookup_table(lookupTableArn=arn)

    # Effect confirmed absent: the table is really gone.
    expected_message = f"Lookup table '{name}' not found in account '{ctx.account}'"
    error = _expect_error(lambda: logs.get_lookup_table(lookupTableArn=arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"GetLookupTable after DeleteLookupTable returned {error!r}, expected "
        f"ResourceNotFoundException"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Negative: deleting the same (now-nonexistent) lookup table again is rejected.
    error = _expect_error(lambda: logs.delete_lookup_table(lookupTableArn=arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"a second DeleteLookupTable on an already-deleted table returned {error!r}, expected "
        f"ResourceNotFoundException"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control in the same file: creating and deleting a brand-new table succeeds.
    name2 = _sanitize_lookup_name(ctx.unique_name("sim2realneglookupctrl"))
    arn2 = logs.create_lookup_table(
        lookupTableName=name2, tableBody=table_body,
        tags={"sim2real": "delete-lookup-table-already-deleted-rejected"},
    )["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete(logs, arn2))
    logs.delete_lookup_table(lookupTableArn=arn2)
    error2 = _expect_error(lambda: logs.get_lookup_table(lookupTableArn=arn2))
    assert error2.get("Code") == "ResourceNotFoundException", (
        f"GetLookupTable after the control DeleteLookupTable returned {error2!r}, expected "
        f"ResourceNotFoundException"
    )
    expected_message2 = f"Lookup table '{name2}' not found in account '{ctx.account}'"
    assert error2.get("Message") == expected_message2, (
        f"expected message {expected_message2!r}, got {error2.get('Message')!r}"
    )


def _sanitize_lookup_name(raw: str) -> str:
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return cleaned or "sim2reallookup"


def _safe_delete(logs, arn: str) -> None:
    try:
        logs.delete_lookup_table(lookupTableArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _expect_error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
