"""list-consumable-resources-rejects-max-results-out-of-range."""
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


CHECK = "list-consumable-resources-rejects-max-results-out-of-range"
GROUP = "consumable-resource"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConsumableResources rejects a maxResults outside 1-100 with ClientException; a
    maxResults of 1 is accepted and the created consumable resource turns up by paginating."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")
    arn = batch.create_consumable_resource(
        consumableResourceName=name, resourceType="REPLENISHABLE", totalQuantity=1
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=arn))

    zero_code, zero_message, zero_request_id = _error_code(
        lambda: batch.list_consumable_resources(maxResults=0)
    )
    assert zero_code == "ClientException", f"expected ClientException for maxResults=0, got {zero_code!r}"
    expected_zero_message = (
        "Error executing request, Exception : Max Results should be greater than 0 and less than or equal to 100, "
        f"RequestId: {zero_request_id}"
    )
    assert zero_message == expected_zero_message, (
        f"expected message {expected_zero_message!r}, got {zero_message!r}"
    )

    over_code, over_message, over_request_id = _error_code(
        lambda: batch.list_consumable_resources(maxResults=101)
    )
    assert over_code == "ClientException", f"expected ClientException for maxResults=101, got {over_code!r}"
    expected_over_message = (
        "Error executing request, Exception : Max Results should be greater than 0 and less than or equal to 100, "
        f"RequestId: {over_request_id}"
    )
    assert over_message == expected_over_message, (
        f"expected message {expected_over_message!r}, got {over_message!r}"
    )

    # Positive control: maxResults=1 is accepted, and the created resource shows up by paginating.
    names = set()
    token = None
    while True:
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = batch.list_consumable_resources(**kwargs)
        assert len(page["consumableResources"]) <= 1, (
            f"maxResults=1 must cap the page at 1 item, got {len(page['consumableResources'])}"
        )
        names.update(c["consumableResourceName"] for c in page["consumableResources"])
        token = page.get("nextToken")
        if not token:
            break
    assert name in names, f"expected {name!r} among paginated consumable resources, got {sorted(names)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
