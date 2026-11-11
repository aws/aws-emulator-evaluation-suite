"""list-consumable-resources-reflects-created."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-consumable-resources-reflects-created"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConsumableResources enumerates created consumable resources and stops listing
    them after deletion."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-consumable-")
    created = batch.create_consumable_resource(
        consumableResourceName=name,
        resourceType="REPLENISHABLE",
        totalQuantity=100,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-consumable"},
    )
    arn = created["consumableResourceArn"]
    assert created["consumableResourceName"] == name, (
        f"CreateConsumableResource must echo the requested name, expected {name!r}, "
        f"got {created['consumableResourceName']!r}"
    )

    def _cleanup():
        _ignore_client_error(lambda: batch.delete_consumable_resource(consumableResource=arn))

    ctx.on_cleanup(_cleanup)

    described = batch.describe_consumable_resource(consumableResource=arn)
    assert described["totalQuantity"] == 100, (
        f"expected totalQuantity 100 right after create, got {described['totalQuantity']!r}"
    )
    assert described["resourceType"] == "REPLENISHABLE", (
        f"expected resourceType REPLENISHABLE, got {described['resourceType']!r}"
    )

    names_before = _poll_until(
        lambda: {c["consumableResourceName"] for c in _list_all_consumable_resources(batch)},
        lambda names: name in names,
        timeout_s=60,
    )
    assert name in names_before, (
        f"ListConsumableResources must include a just-created resource, {name!r} was absent"
    )
    matching = [c for c in _list_all_consumable_resources(batch) if c["consumableResourceName"] == name]
    assert len(matching) == 1, f"expected exactly one list entry for {name!r}, got {len(matching)}"
    assert matching[0]["totalQuantity"] == 100, (
        f"list entry for {name!r} must report totalQuantity 100, got {matching[0]['totalQuantity']!r}"
    )

    batch.delete_consumable_resource(consumableResource=arn)

    names_after = _poll_until(
        lambda: {c["consumableResourceName"] for c in _list_all_consumable_resources(batch)},
        lambda names: name not in names,
        timeout_s=60,
    )
    assert name not in names_after, (
        f"ListConsumableResources must stop reflecting {name!r} once it is deleted"
    )
    describe_code, describe_message = _error(lambda: batch.describe_consumable_resource(consumableResource=arn))
    assert describe_code == "ClientException", (
        f"describing a deleted consumable resource must raise ClientException, got {describe_code!r}"
    )
    expected_message = f"{arn} does not exist"
    assert describe_message == expected_message, f"expected message {expected_message!r}, got {describe_message!r}"
    # Measured, not assumed: DeleteConsumableResource on an already-deleted resource is
    # idempotent (no error), even though DescribeConsumableResource above already treats
    # the same ARN as gone.
    # A raise here fails the check: the repeated delete must be a no-op.
    batch.delete_consumable_resource(consumableResource=arn)


def _error(fn: Callable[[], Any]):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ignore_client_error(fn: Callable[[], Any]) -> None:
    """Best-effort teardown step: a ClientError (already gone) is ignored."""
    from botocore.exceptions import ClientError

    fn()


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
