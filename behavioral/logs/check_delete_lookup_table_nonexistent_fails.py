"""delete-lookup-table-nonexistent-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-lookup-table-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLookupTable on a well-formed but never-created ARN raises ResourceNotFoundException with its
    exact message, and the real lookup table it was derived from is unaffected."""
    logs = ctx.client("logs")

    name = _lookup_table_name(ctx)
    real_arn = logs.create_lookup_table(
        lookupTableName=name, tableBody="id,label\n1,a\n2,b\n"
    )["lookupTableArn"]
    ctx.on_cleanup(lambda: _safe_delete(logs, real_arn))

    # Positive control: the real table is live and reachable.
    logs.get_lookup_table(lookupTableArn=real_arn)

    bogus_arn = real_arn + "_absent"

    error = _expect_error(lambda: logs.delete_lookup_table(lookupTableArn=bogus_arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DeleteLookupTable on an unknown "
        f"ARN, got {error!r}"
    )
    expected_message = f"Lookup table '{name}_absent' not found in account '{ctx.account}'"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Independent terminal read: the real table is unaffected by the rejected
    # delete on the never-created ARN.
    still_there = logs.get_lookup_table(lookupTableArn=real_arn)
    assert still_there["lookupTableArn"] == real_arn, (
        f"expected the real table to still exist after the rejected delete on "
        f"a sibling ARN, got {still_there}"
    )


def _lookup_table_name(ctx: Any) -> str:
    # lookupTableName pattern is ^[a-zA-Z0-9_]+$ -- ctx.unique_name emits hyphens, so sanitize.
    return ctx.unique_name("sim2real_behav_nosuchtbl_").replace("-", "_")


def _safe_delete(logs: Any, arn: str) -> None:
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
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
