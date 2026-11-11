"""lowering-the-minimum-does-not-scale-capacity-in."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lowering-the-minimum-does-not-scale-capacity-in"
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
    """Bound enforcement is edge-triggered: raising MinCapacity to 8 drags read capacity from 1 to
    8, and lowering it back to 1 leaves capacity at 8: a later MaxCapacity cut to 6 is the only new
    scaling activity.
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

    first = _activities(aas, resource_id)
    assert len(first) == 1, (
        f"raising the floor produced {len(first)} scaling activities, expected exactly one: "
        f"{[(a['Cause'], a['Description']) for a in first]!r}"
    )
    assert first[0]["Cause"] == "minimum capacity was set to 8", (
        f"the activity's Cause was {first[0]['Cause']!r}; real AWS attributes the move to the "
        f"bound that caused it"
    )
    assert first[0]["Description"] == "Setting read capacity units to 8.", (
        f"the activity described itself as {first[0]['Description']!r}, expected "
        f"'Setting read capacity units to 8.'"
    )

    # Relax the floor all the way back. The live capacity of 8 now violates nothing.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=10,
    )
    target = _targets_for(aas, resource_id)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 10), (
        f"the registered bounds read back as "
        f"({target['MinCapacity']}, {target['MaxCapacity']}), expected the relaxed (1, 10)"
    )

    assert _read_capacity(ddb, table) == 8, (
        f"read capacity moved to {_read_capacity(ddb, table)} after the floor was relaxed to 1; a "
        f"floor is a bound that is enforced when crossed, not a value the service converges on"
    )

    # Positive control ordered after the relaxation: a ceiling of 6 must scale capacity in with its
    # own activity, and by the time it appears no activity for the relaxed floor may exist.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=6,
    )
    after = _poll_until(
        ctx,
        lambda: _activities(aas, resource_id),
        lambda acts: any(a.get("Description") == "Setting read capacity units to 6." for a in acts),
        timeout_s=240,
        description="the activity scaling read capacity in to the new ceiling of 6",
    )
    assert len(after) == 2, (
        f"relaxing the floor emitted a further scaling activity: "
        f"{[(a['Cause'], a['Description']) for a in after]!r}; only the original floor raise and "
        f"the ceiling-of-6 activity may appear, because nothing was scaled by the relaxation"
    )
    assert first[0]["ActivityId"] in [a["ActivityId"] for a in after], (
        f"the recorded activity {first[0]['ActivityId']!r} is no longer listed; the floor "
        f"relaxation must not rewrite history"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
