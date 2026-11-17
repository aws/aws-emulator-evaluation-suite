"""list-jobs-by-consumable-resource-rejects-max-results-out-of-range."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "list-jobs-by-consumable-resource-rejects-max-results-out-of-range"
GROUP = "consumable-resource"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListJobsByConsumableResource rejects a maxResults outside 1-1000 with ClientException; a
    maxResults of 1 against the same consumable resource is accepted and returns no jobs."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")
    arn = batch.create_consumable_resource(
        consumableResourceName=name, resourceType="REPLENISHABLE", totalQuantity=1
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=arn))

    zero_code, zero_message, zero_request_id = _error_code(
        lambda: batch.list_jobs_by_consumable_resource(consumableResource=arn, maxResults=0)
    )
    assert zero_code == "ClientException", f"expected ClientException for maxResults=0, got {zero_code!r}"
    expected_zero_message = (
        "Error executing request, Exception : Max Results should be greater than 0 and less "
        f"than or equal to 1000, RequestId: {zero_request_id}"
    )
    assert zero_message == expected_zero_message, (
        f"expected message {expected_zero_message!r}, got {zero_message!r}"
    )

    over_code, over_message, over_request_id = _error_code(
        lambda: batch.list_jobs_by_consumable_resource(consumableResource=arn, maxResults=1001)
    )
    assert over_code == "ClientException", f"expected ClientException for maxResults=1001, got {over_code!r}"
    expected_over_message = (
        "Error executing request, Exception : Max Results should be greater than 0 and less "
        f"than or equal to 1000, RequestId: {over_request_id}"
    )
    assert over_message == expected_over_message, (
        f"expected message {expected_over_message!r}, got {over_message!r}"
    )

    # Positive control: maxResults=1 against the same resource is accepted; no job ever used it.
    accepted = batch.list_jobs_by_consumable_resource(consumableResource=arn, maxResults=1)
    assert accepted["jobs"] == [], f"expected no jobs for an unused consumable resource, got {accepted['jobs']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
