"""external-capacity-change-below-floor-not-reverted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "external-capacity-change-below-floor-not-reverted"
GROUP = "data-plane"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _create_provisioned_table(ctx, ddb, read_cap, write_cap):
    name = ctx.unique_name("sim2real-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180,
        interval_s=2.0,
        description=f"table {name!r} becoming ACTIVE",
    )
    return name


def _delete_table(ddb, name):
    for _ in range(12):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise RuntimeError(f"table {name!r} not deleted: {code}") from exc
            time.sleep(6)
    raise RuntimeError(f"table {name!r} still ResourceInUseException after retries")


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ObjectNotFoundException":
            raise


def _activities(aas, resource_id):
    out, token = [], None
    while True:
        kwargs = {"ServiceNamespace": _NS, "ResourceId": resource_id, "ScalableDimension": _DIM}
        if token:
            kwargs["NextToken"] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page["ScalingActivities"])
        token = page.get("NextToken")
        if not token:
            return out


def _targets_for(aas, resource_id):
    out, token = [], None
    while True:
        kwargs = {"ServiceNamespace": _NS, "ResourceIds": [resource_id]}
        if token:
            kwargs["NextToken"] = token
        page = aas.describe_scalable_targets(**kwargs)
        out.extend(page["ScalableTargets"])
        token = page.get("NextToken")
        if not token:
            break
    mine = [t for t in out if t["ScalableDimension"] == _DIM]
    assert len(mine) == 1, f"expected exactly one scalable target for {resource_id!r}, saw {mine!r}"
    return mine[0]


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)["Table"]["ProvisionedThroughput"][
        "ReadCapacityUnits"
    ]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """After the registration floor of 8 is applied and fulfilled, a direct DynamoDB decrease to 2 is
    not reverted: MinCapacity still reads 8, and a later floor change to 9 is the only new activity.
    """
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")
    table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    resource_id = f"table/{table}"

    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=8,
        MaxCapacity=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    raised = _poll_until(
        ctx,
        lambda: _read_capacity(ddb, table),
        lambda cap: cap == 8,
        timeout_s=180,
        interval_s=2.0,
        description=f"a registered floor of 8 dragging table {table!r} read capacity up from 1",
    )
    assert raised == 8, f"table read capacity settled at {raised!r}, expected the floor of 8"

    # Wait for the activity to be FULFILLED before interfering. An activity still waiting on
    # DynamoDB resolves to Overridden instead, which is a different behaviour and a different
    # check; here the floor has been fully applied and Application Auto Scaling is done.
    settled = _poll_until(
        ctx,
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) == 1 and acts[0]["StatusCode"] == "Successful",
        timeout_s=240,
        interval_s=2.0,
        description="the floor-raise activity reaching a fulfilled Successful state",
    )
    assert settled[0]["StatusMessage"] == (
        "Successfully set read capacity units to 8. Change successfully fulfilled by dynamodb."
    ), (
        f"the fulfilled activity's StatusMessage was {settled[0]['StatusMessage']!r}; real AWS "
        f"confirms fulfilment by naming the downstream service that applied the change"
    )
    fulfilled_id = settled[0]["ActivityId"]

    # Take the table below its own registered floor, from outside Application Auto Scaling.
    ddb.update_table(
        TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 1}
    )
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180,
        interval_s=2.0,
        description=f"table {table!r} returning to ACTIVE after the direct capacity decrease",
    )
    assert _read_capacity(ddb, table) == 2, (
        f"the direct decrease left read capacity at {_read_capacity(ddb, table)}, expected 2; the "
        f"check cannot say anything about reversion if the decrease never landed"
    )

    target = _targets_for(aas, resource_id)
    assert target["MinCapacity"] == 8, (
        f"the registered MinCapacity reads {target['MinCapacity']!r} after the table was taken "
        f"below it; the registration is unchanged -- it is the enforcement that is not continuous, "
        f"not the record that was rewritten"
    )

    # Positive control ordered after the decrease: a new floor of 9 must produce its own activity,
    # and by the time it appears no corrective activity for the floor of 8 may exist.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=9,
        MaxCapacity=10,
    )
    final = _poll_until(
        ctx,
        lambda: _activities(aas, resource_id),
        lambda acts: any("capacity units to 9" in a.get("Description", "") for a in acts),
        timeout_s=240,
        description="the activity raising read capacity to the new floor of 9",
    )
    assert len(final) == 2, (
        f"the direct decrease provoked further scaling activities: "
        f"{[(a['Cause'], a['StatusMessage']) for a in final]!r}; expected only the original "
        f"floor raise and the floor-of-9 activity, because no corrective scaling happened"
    )
    original = [a for a in final if a["ActivityId"] == fulfilled_id]
    assert len(original) == 1, (
        f"the fulfilled activity {fulfilled_id!r} is no longer listed; saw "
        f"{[a['ActivityId'] for a in final]!r}"
    )
    assert original[0]["StatusCode"] == "Successful", (
        f"the already-fulfilled activity moved to {original[0]['StatusCode']!r} after the external "
        f"change; an activity confirmed fulfilled is terminal and does not retroactively become "
        f"Overridden"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
