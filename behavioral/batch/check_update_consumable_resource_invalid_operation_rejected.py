"""update-consumable-resource-invalid-operation-rejected."""
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


CHECK = "update-consumable-resource-invalid-operation-rejected"
GROUP = "consumable-resource"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConsumableResource rejects an operation outside SET / ADD / REMOVE with
    ClientException and leaves the total quantity unchanged; SET for the identical resource
    succeeds."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")
    arn = batch.create_consumable_resource(
        consumableResourceName=name, resourceType="REPLENISHABLE", totalQuantity=10
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=arn))

    code, message, request_id = _error_code(
        lambda: batch.update_consumable_resource(consumableResource=arn, operation="MULTIPLY", quantity=5)
    )
    assert code == "ClientException", f"expected ClientException for operation=MULTIPLY, got {code!r}"
    expected_message = (
        "Error executing request, Exception : Update operation needs to be one of the following "
        f"values: [SET, ADD, REMOVE], RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = batch.describe_consumable_resource(consumableResource=arn)
    assert unchanged["totalQuantity"] == 10, (
        f"a refused update must leave totalQuantity unchanged, got {unchanged['totalQuantity']!r}"
    )

    # Positive control: the same resource, a valid operation.
    accepted = batch.update_consumable_resource(consumableResource=arn, operation="SET", quantity=20)
    assert accepted["totalQuantity"] == 20, f"expected SET to 20, got {accepted['totalQuantity']!r}"
    confirmed = batch.describe_consumable_resource(consumableResource=arn)
    assert confirmed["totalQuantity"] == 20, (
        f"expected 20 on an independent read, got {confirmed['totalQuantity']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
