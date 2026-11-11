"""register-below-namespace-minimum-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-below-namespace-minimum-rejected"
GROUP = "bounds-rejected"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
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


def _error(fn, *args, **kwargs):
    """Return (code, message) for a call expected to fail. Raise if it unexpectedly succeeds."""
    try:
        result = fn(*args, **kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}; a target that "
        f"accepts input real AWS refuses is the strongest over-permissiveness signal there is"
    )


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
    """Every registered target for exactly this ResourceId -- a query-scoped listing."""
    out, token = [], None
    while True:
        kwargs = {"ServiceNamespace": _NS, "ResourceIds": [resource_id]}
        if token:
            kwargs["NextToken"] = token
        page = aas.describe_scalable_targets(**kwargs)
        out.extend(page["ScalableTargets"])
        token = page.get("NextToken")
        if not token:
            return out


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)["Table"]["ProvisionedThroughput"][
        "ReadCapacityUnits"
    ]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RegisterScalableTarget refuses MinCapacity 0 for a DynamoDB capacity dimension and leaves no
    registration and no change to the table; the boundary value 1 registers and moves capacity.
    """
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")
    table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    resource_id = f"table/{table}"

    code, message = _error(
        aas.register_scalable_target,
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        # The model declares no range floor; 0 is below the DynamoDB namespace minimum.
        MinCapacity=0,
        MaxCapacity=5,
    )
    assert code == "ValidationException", (
        f"registering MinCapacity=0 was rejected as {code!r}; real AWS raises ValidationException "
        f"for a capacity below the DynamoDB namespace's own floor of 1"
    )
    assert message == "Minimum capacity cannot be less than 1", (
        f"the rejection message was {message!r}; real AWS names the floor it enforced, which is "
        f"the only way a caller learns a bound the Smithy model does not declare"
    )

    assert _targets_for(aas, resource_id) == [], (
        f"the refused registration left a scalable target behind for {resource_id!r}: "
        f"{_targets_for(aas, resource_id)!r}; a rejected register must register nothing"
    )
    assert _activities(aas, resource_id) == [], (
        f"the refused registration emitted scaling activities: "
        f"{_activities(aas, resource_id)!r}; nothing was scaled, so nothing may be recorded"
    )
    assert _read_capacity(ddb, table) == 1, (
        f"table read capacity is {_read_capacity(ddb, table)} after the refused registration; it "
        f"was created with 1 and no accepted request has asked for anything else"
    )

    # Positive control: 1 is the boundary and it is accepted, and enforcement then works.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    registered = _targets_for(aas, resource_id)
    assert len(registered) == 1 and registered[0]["MinCapacity"] == 1, (
        f"the boundary value MinCapacity=1 did not register as exactly one target with a minimum "
        f"of 1: {registered!r}"
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=3,
        MaxCapacity=5,
    )
    moved = _poll_until(
        lambda: _read_capacity(ddb, table),
        lambda cap: cap == 3,
        timeout_s=180,
        interval_s=3.0,
        description=(
            "the positive control: a floor of 3 moving real table read capacity, proving the "
            "refusal of 0 was about the value and not about a dead enforcement pipeline"
        ),
    )
    assert moved == 3, f"the positive-control floor of 3 left read capacity at {moved!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
