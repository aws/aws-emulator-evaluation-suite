"""superseded-scaling-activity-resolves-to-overridden."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "superseded-scaling-activity-resolves-to-overridden"
GROUP = "data-plane"
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
    """A scaling activity whose capacity a later activity changes again settles on Overridden,
    with a StatusMessage naming the displacing value; the later activity settles Successful.
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
        lambda: _read_capacity(ddb, table),
        lambda cap: cap == 8,
        timeout_s=180,
        interval_s=3.0,
        description=f"a registered floor of 8 dragging table {table!r} read capacity up from 1",
    )
    assert raised == 8, f"table read capacity settled at {raised!r}, expected the floor of 8"

    # The ceiling drop supersedes the floor raise: both write real capacity, in that order.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=4,
    )
    lowered = _poll_until(
        lambda: _read_capacity(ddb, table),
        lambda cap: cap == 4,
        timeout_s=180,
        interval_s=3.0,
        description=f"a registered ceiling of 4 pushing table {table!r} read capacity down from 8",
    )
    assert lowered == 4, f"table read capacity settled at {lowered!r}, expected the ceiling of 4"

    def _both_terminal():
        acts = _activities(aas, resource_id)
        if len(acts) != 2:
            return None
        if acts[0]["StatusCode"] == "InProgress" or acts[1]["StatusCode"] == "InProgress":
            return None
        return acts

    acts = _poll_until(
        _both_terminal,
        lambda a: a is not None,
        timeout_s=240,
        interval_s=5.0,
        description="both scaling activities leaving InProgress",
    )
    newest, oldest = acts[0], acts[1]

    assert oldest["Cause"] == "minimum capacity was set to 8", (
        f"the older activity's Cause was {oldest['Cause']!r}; the floor raise is recorded as "
        f"'minimum capacity was set to 8'"
    )
    assert newest["Cause"] == "maximum capacity was set to 4", (
        f"the newer activity's Cause was {newest['Cause']!r}; the ceiling drop is recorded as "
        f"'maximum capacity was set to 4'"
    )
    assert newest["StatusCode"] == "Successful", (
        f"the surviving activity resolved to {newest['StatusCode']!r}; the last activity to move "
        f"capacity is the one that owns it and must read 'Successful'"
    )
    assert newest["StatusMessage"] == (
        "Successfully set read capacity units to 4. Change successfully fulfilled by dynamodb."
    ), (
        f"the surviving activity's StatusMessage was {newest['StatusMessage']!r}; real AWS confirms "
        f"fulfilment by naming the downstream service"
    )
    assert oldest["StatusCode"] == "Overridden", (
        f"the superseded activity resolved to {oldest['StatusCode']!r}, not 'Overridden'; an "
        f"activity whose capacity was displaced before fulfilment was confirmed is Overridden, and "
        f"reporting it Successful loses the distinction entirely"
    )
    assert oldest["StatusMessage"] == (
        "Successfully set read capacity units to 8. Found it was later changed to 4."
    ), (
        f"the superseded activity's StatusMessage was {oldest['StatusMessage']!r}; real AWS names "
        f"the displacing value (4) in the message rather than only flipping the status code"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
