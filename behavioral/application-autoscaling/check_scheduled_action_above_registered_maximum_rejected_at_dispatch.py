"""scheduled-action-above-registered-maximum-rejected-at-dispatch."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-above-registered-maximum-rejected-at-dispatch"
GROUP = "scheduled-action-rejected"
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


def _delete_action(aas, resource_id, action):
    try:
        aas.delete_scheduled_action(
            ServiceNamespace=_NS,
            ResourceId=resource_id,
            ScalableDimension=_DIM,
            ScheduledActionName=action,
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


def _scheduled_actions(aas, resource_id):
    out, token = [], None
    while True:
        kwargs = {"ServiceNamespace": _NS, "ResourceId": resource_id, "ScalableDimension": _DIM}
        if token:
            kwargs["NextToken"] = token
        page = aas.describe_scheduled_actions(**kwargs)
        out.extend(page["ScheduledActions"])
        token = page.get("NextToken")
        if not token:
            return out


def _scalable_target(aas, resource_id):
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


def _next_cron_minute(min_lead_s=25):
    """The next whole UTC minute at least ``min_lead_s`` away, as a one-shot cron expression."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f"cron({fire.minute} {fire.hour} {fire.day} {fire.month} ? {fire.year})", fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A scheduled minimum above the registered maximum is accepted at PutScheduledAction and
    fails at dispatch: the activity is Failed, the bounds are untouched, capacity never moves.
    """
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")
    table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    resource_id = f"table/{table}"
    action = ctx.unique_name("sim2real-aas-sa-")

    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    schedule, fire_at = _next_cron_minute()
    # 25 is above the registered MaxCapacity of 10; AWS defers the bounds check to dispatch.
    aas.put_scheduled_action(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        ScheduledActionName=action,
        Schedule=schedule,
        Timezone="UTC",
        ScalableTargetAction={"MinCapacity": 25},
    )
    ctx.on_cleanup(lambda: _delete_action(aas, resource_id, action))

    stored = [a for a in _scheduled_actions(aas, resource_id) if a["ScheduledActionName"] == action]
    assert len(stored) == 1, (
        f"the out-of-range scheduled action did not come back as exactly one stored entry: "
        f"{stored!r}; PutScheduledAction accepted it, so it must be readable"
    )
    assert stored[0]["ScalableTargetAction"] == {"MinCapacity": 25}, (
        f"the stored ScalableTargetAction was {stored[0]['ScalableTargetAction']!r}; real AWS "
        f"persists the out-of-range minimum verbatim rather than clamping it to the registered "
        f"maximum of 10"
    )

    dispatched = _poll_until(
        lambda: [a for a in _activities(aas, resource_id) if a["StatusCode"] != "InProgress"],
        lambda acts: len(acts) >= 1,
        timeout_s=240,
        interval_s=5.0,
        description=(
            f"the scheduled action {action!r} being dispatched at {fire_at.isoformat()} and "
            f"reaching a terminal state"
        ),
    )
    assert len(dispatched) == 1, (
        f"expected exactly one activity -- the refused dispatch -- but saw {len(dispatched)}: "
        f"{[(a['Cause'], a['StatusCode'], a['StatusMessage']) for a in dispatched]!r}"
    )
    activity = dispatched[0]
    assert activity["StatusCode"] == "Failed", (
        f"the dispatch activity resolved to {activity['StatusCode']!r}; a scheduled minimum above "
        f"the registered maximum must fail, not succeed and not silently clamp"
    )
    assert activity["Cause"] == f"scheduled action name {action} was triggered", (
        f"the dispatch activity's Cause was {activity['Cause']!r}; real AWS writes "
        f"'scheduled action name {action} was triggered' even when the dispatch then fails"
    )
    assert activity["Description"] == "Setting min capacity to 25", (
        f"the dispatch activity described itself as {activity['Description']!r}, expected "
        f"'Setting min capacity to 25'"
    )
    assert activity["StatusMessage"] == (
        "Failed to set min capacity to 25. Reason: Maximum capacity cannot be less than minimum "
        "capacity"
    ), (
        f"the dispatch failure message was {activity['StatusMessage']!r}; real AWS reports the "
        f"same inverted-bounds reason that PutScheduledAction would have returned inline"
    )

    target = _scalable_target(aas, resource_id)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 10), (
        f"the registered bounds are ({target['MinCapacity']}, {target['MaxCapacity']}) after the "
        f"refused dispatch; a failed scheduled action must leave the bounds it could not apply "
        f"exactly as they were"
    )
    assert _read_capacity(ddb, table) == 1, (
        f"table read capacity is {_read_capacity(ddb, table)} after the refused dispatch; the "
        f"effect must be wholly absent, not partially applied"
    )

    # Positive control: an in-range floor does move capacity, so the refusal was about the value.
    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=4,
        MaxCapacity=10,
    )
    moved = _poll_until(
        lambda: _read_capacity(ddb, table),
        lambda cap: cap == 4,
        timeout_s=180,
        interval_s=3.0,
        description=(
            "the positive control: an in-range floor of 4 moving real table read capacity, "
            "proving the refusal above was about the out-of-range value and not a dead pipeline"
        ),
    )
    assert moved == 4, f"the positive-control floor of 4 left read capacity at {moved!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
