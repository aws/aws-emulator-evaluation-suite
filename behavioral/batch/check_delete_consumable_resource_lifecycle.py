"""delete-consumable-resource-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-consumable-resource-lifecycle"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConsumableResource removes an existing resource but rejects an unknown one."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")

    resp = batch.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=10,
        resourceType="REPLENISHABLE",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-cr", "sim2real": CHECK},
    )
    arn = resp["consumableResourceArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, arn))

    described = batch.describe_consumable_resource(consumableResource=arn)
    assert described["consumableResourceName"] == name, (
        f"expected consumableResourceName {name!r}, got {described.get('consumableResourceName')!r}"
    )
    assert described["totalQuantity"] == 10, (
        f"expected totalQuantity 10, got {described.get('totalQuantity')!r}"
    )

    # Negative: a malformed consumable resource identifier (invalid characters) is rejected.
    bogus_arn = "!! not a valid consumable resource identifier !!"
    code, message = _error_code(lambda: batch.delete_consumable_resource(consumableResource=bogus_arn))
    assert code == "ClientException", f"expected ClientException for malformed identifier, got {code}"
    expected = f"Provided name {bogus_arn} is not supported pattern[a-zA-Z_0-9-]{{1,128}}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The real resource must be unaffected by the failed delete of the bogus one.
    still_there = batch.describe_consumable_resource(consumableResource=arn)
    assert still_there["consumableResourceName"] == name, (
        f"failed delete of a bogus identifier must not affect the real resource: "
        f"expected name {name!r}, got {still_there.get('consumableResourceName')!r}"
    )

    # Positive control: deleting the real, unreferenced resource succeeds.
    batch.delete_consumable_resource(consumableResource=arn)

    deadline = time.monotonic() + 60
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            batch.describe_consumable_resource(consumableResource=arn)
        except ClientError as err:
            last_code, last_message = err.response["Error"]["Code"], err.response["Error"].get("Message")
            break
        time.sleep(3)
    assert last_code == "ClientException", "deleted consumable resource is still describable"
    expected_gone = f"{arn} does not exist"
    assert last_message == expected_gone, f"expected message {expected_gone!r}, got {last_message!r}"

    # A mutation on the dead id must also fail, not just the read.
    mutate_code, mutate_message = _error_code(
        lambda: batch.update_consumable_resource(consumableResource=arn, operation="ADD", quantity=1)
    )
    assert mutate_code == "ClientException", (
        f"expected ClientException updating a deleted consumable resource, got {mutate_code}"
    )
    assert mutate_message == expected_gone, f"expected message {expected_gone!r}, got {mutate_message!r}"

    # The name is reusable once the original resource is gone.
    reused = batch.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=1,
        resourceType="REPLENISHABLE",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-cr", "sim2real": CHECK},
    )
    reused_arn = reused["consumableResourceArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, reused_arn))
    redescribed = batch.describe_consumable_resource(consumableResource=reused_arn)
    assert redescribed["consumableResourceName"] == name, (
        f"expected the reused name {name!r} back on describe, got {redescribed.get('consumableResourceName')!r}"
    )
    # The ARN is derived from account/region/name, so recreating under the same name
    # after a real delete yields the SAME ARN back.
    assert reused_arn == arn, (
        f"expected the recreated resource's ARN to match the freed name's ARN {arn!r}, got {reused_arn!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _best_effort_delete(batch: Any, arn: str) -> None:
    batch.delete_consumable_resource(consumableResource=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
