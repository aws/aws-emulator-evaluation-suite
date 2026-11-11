"""create-consumable-resource-invalid-type-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-consumable-resource-invalid-type-rejected"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConsumableResource rejects a resourceType outside the REPLENISHABLE /
    NON_REPLENISHABLE enum with ClientException and creates nothing; the same call with a
    valid resourceType (positive control) succeeds."""
    batch = ctx.client("batch")
    bad_name = ctx.unique_name("sim2real-consumable-bad-")

    code, message, request_id = _error_code(
        lambda: batch.create_consumable_resource(
            consumableResourceName=bad_name, resourceType="INFINITE", totalQuantity=10
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : resourceType needs to be one of the following "
        f"values: [REPLENISHABLE, NON_REPLENISHABLE], RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect did not happen: no consumable resource with that name exists.
    names = {c["consumableResourceName"] for c in _list_all_consumable_resources(batch)}
    assert bad_name not in names

    # Positive control: the same shape with a valid resourceType succeeds.
    good_name = ctx.unique_name("sim2real-consumable-good-")
    created = batch.create_consumable_resource(
        consumableResourceName=good_name, resourceType="NON_REPLENISHABLE", totalQuantity=10
    )
    arn = created["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=arn))
    described = batch.describe_consumable_resource(consumableResource=arn)
    assert described["resourceType"] == "NON_REPLENISHABLE"
    assert described["totalQuantity"] == 10


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
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _list_all_consumable_resources(batch):
    out = []
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_consumable_resources(**kwargs)
        out.extend(resp.get("consumableResources", []))
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
