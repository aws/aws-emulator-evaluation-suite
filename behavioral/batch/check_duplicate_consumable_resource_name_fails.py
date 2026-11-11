"""duplicate-consumable-resource-name-fails."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "duplicate-consumable-resource-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-cr"}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.
    Unexpected success raises, so acceptance is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _describe_consumable_resource(bat, name):
    return bat.describe_consumable_resource(consumableResource=name)


def _create_consumable_resource(ctx, bat, name=None, total_quantity=10, resource_type="REPLENISHABLE"):
    name = name or ctx.unique_name("sim2real-behav-cr-")
    resp = bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=total_quantity,
        resourceType=resource_type,
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=name)))
    return name, resp["consumableResourceArn"]


def _wait_not_found(bat, arn, timeout_s=60, interval_s=3):
    """Poll describe on the deleted arn until it reports ClientException (gone)."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            bat.describe_consumable_resource(consumableResource=arn)
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            if last_code == "ClientException":
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"deleted consumable resource {arn} still describable after {timeout_s}s "
        f"(last_code={last_code!r})"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a consumable resource with an existing name is rejected, and once that resource is
    gone the same create succeeds, so the name conflict is scoped to the live resource."""
    bat = ctx.client("batch")
    name, arn = _create_consumable_resource(ctx, bat, total_quantity=5, resource_type="REPLENISHABLE")

    code, message = _error(lambda: bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=99,
        resourceType="REPLENISHABLE",
        tags=dict(_MANAGED_TAGS),
    ))
    assert code == "ClientException", (
        f"expected ClientException for duplicate consumable resource name, got {code!r}"
    )
    assert message == "Object already exists", f"expected message 'Object already exists', got {message!r}"

    # The rejected create must not have clobbered the original quantity.
    d = _describe_consumable_resource(bat, name)
    assert d["totalQuantity"] == 5, f"duplicate create mutated the original: {d['totalQuantity']}"

    # Restore: the conflict is with the LIVE resource, not the name forever. Delete the
    # original, wait for it to actually be gone, then the identical create must now succeed.
    bat.delete_consumable_resource(consumableResource=arn)
    _wait_not_found(bat, arn)
    _create_consumable_resource(ctx, bat, name=name, total_quantity=99, resource_type="REPLENISHABLE")
    d2 = _describe_consumable_resource(bat, name)
    assert d2["totalQuantity"] == 99, f"post-restore create did not land: {d2['totalQuantity']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
