"""billing-group-lifecycle-and-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "billing-group-lifecycle-and-membership"
GROUP = 'billing-group'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

def _delete_billing_group(iot, name):
    """Best-effort teardown: delete a billing group (thing associations dissolve with it)."""
    iot.delete_billing_group(billingGroupName=name)

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBillingGroup -> Add/Remove thing -> Update -> List -> Delete, with the
    membership listing reflecting each transition."""
    iot = ctx.client("iot")
    group = ctx.unique_name("sim2real-behav-bg-")
    thing = ctx.unique_name("sim2real-behav-thing-bg-")
    created = iot.create_billing_group(
        billingGroupName=group,
        billingGroupProperties={"billingGroupDescription": "initial"},
    )
    ctx.on_cleanup(lambda _n=group: _delete_billing_group(iot, _n))
    assert created["billingGroupName"] == group, f"expected {group}, got {created['billingGroupName']}"
    assert "billingGroupArn" in created, f"CreateBillingGroup response missing billingGroupArn: {created}"

    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    desc = iot.describe_billing_group(billingGroupName=group)
    assert desc["billingGroupProperties"]["billingGroupDescription"] == "initial", (
        f"expected description 'initial', got {desc['billingGroupProperties']!r}"
    )
    version = desc["version"]

    iot.add_thing_to_billing_group(billingGroupName=group, thingName=thing)
    members = _eventually(
        lambda: iot.list_things_in_billing_group(billingGroupName=group).get("things", []),
        lambda m: thing in m,
        timeout_s=30,
        interval_s=2.0,
    )
    assert thing in members, members

    iot.remove_thing_from_billing_group(billingGroupName=group, thingName=thing)
    _eventually(
        lambda: iot.list_things_in_billing_group(billingGroupName=group).get("things", []),
        lambda m: thing not in m,
        timeout_s=30,
        interval_s=2.0,
    )

    iot.update_billing_group(
        billingGroupName=group,
        billingGroupProperties={"billingGroupDescription": "updated"},
        expectedVersion=version,
    )
    desc2 = iot.describe_billing_group(billingGroupName=group)
    assert desc2["billingGroupProperties"]["billingGroupDescription"] == "updated", (
        f"expected description 'updated', got {desc2['billingGroupProperties']!r}"
    )
    assert desc2["version"] == version + 1, f"update must bump version, got {desc2['version']}"

    names = [g["groupName"] for g in iot.list_billing_groups().get("billingGroups", [])]
    assert group in names, f"{group} missing from ListBillingGroups"

    iot.delete_billing_group(billingGroupName=group)
    code = _err(lambda: iot.describe_billing_group(billingGroupName=group))
    assert code == ("ResourceNotFoundException", f"BillingGroup {ctx.account}:{group} not found."), (
        f"expected ResourceNotFoundException for the deleted billing group, got {code!r}"
    )

    # The dead id must also reject mutation, not just reads.
    update_code = _err(
        lambda: iot.update_billing_group(
            billingGroupName=group,
            billingGroupProperties={"billingGroupDescription": "post-delete"},
        )
    )
    assert update_code == ("ResourceNotFoundException", f"Group !{group} does not exist"), (
        f"UpdateBillingGroup on a deleted billing group must fail with "
        f"ResourceNotFoundException, got {update_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
