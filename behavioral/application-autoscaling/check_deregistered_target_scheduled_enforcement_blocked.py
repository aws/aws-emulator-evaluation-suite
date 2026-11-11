"""deregistered-target-scheduled-enforcement-blocked."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregistered-target-scheduled-enforcement-blocked"
GROUP = "deregistration-blocked"
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


def _next_cron_minute(min_lead_s=40):
    """The next whole UTC minute at least ``min_lead_s`` away, as a one-shot cron expression."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f"cron({fire.minute} {fire.hour} {fire.day} {fire.month} ? {fire.year})", fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Deregistering a target stops its scheduled action from firing: of two tables armed for the
    same instant, only the still-registered one has its read capacity raised to 5 and an activity
    recorded.
    """
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    # Both tables are created before either is registered, so the two arms are symmetric.
    kept_table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    dropped_table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    kept_id, dropped_id = f"table/{kept_table}", f"table/{dropped_table}"
    for name in (kept_table, dropped_table):
        _poll_until(
            lambda n=name: ddb.describe_table(TableName=n)["Table"]["TableStatus"],
            lambda s: s == "ACTIVE",
            timeout_s=180,
            interval_s=2.0,
            description=f"table {name!r} becoming ACTIVE",
        )

    action = ctx.unique_name("sim2real-aas-sa-")
    schedule, fire_at = _next_cron_minute()
    for resource_id in (kept_id, dropped_id):
        aas.register_scalable_target(
            ServiceNamespace=_NS,
            ResourceId=resource_id,
            ScalableDimension=_DIM,
            MinCapacity=1,
            MaxCapacity=10,
            Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))
        aas.put_scheduled_action(
            ServiceNamespace=_NS,
            ResourceId=resource_id,
            ScalableDimension=_DIM,
            ScheduledActionName=action,
            Schedule=schedule,
            Timezone="UTC",
            ScalableTargetAction={"MinCapacity": 5},
        )
        ctx.on_cleanup(lambda r=resource_id: _delete_action(aas, r, action))

    for resource_id in (kept_id, dropped_id):
        armed = [
            a["ScheduledActionName"] for a in _scheduled_actions(aas, resource_id)
        ]
        assert armed == [action], (
            f"{resource_id!r} was not armed with exactly the one scheduled action {action!r} "
            f"before the withdrawal: {armed!r}; both arms must start identical"
        )

    # Withdraw enforcement from one arm only, well before the scheduled instant.
    aas.deregister_scalable_target(
        ServiceNamespace=_NS, ResourceId=dropped_id, ScalableDimension=_DIM
    )
    assert _targets_for(aas, dropped_id) == [], (
        f"{dropped_id!r} is still a registered scalable target after DeregisterScalableTarget: "
        f"{_targets_for(aas, dropped_id)!r}"
    )
    assert _scheduled_actions(aas, dropped_id) == [], (
        f"the scheduled action survived deregistration on {dropped_id!r}: "
        f"{_scheduled_actions(aas, dropped_id)!r}; deregistration cascades to scheduled actions"
    )
    assert len(_targets_for(aas, kept_id)) == 1, (
        f"deregistering {dropped_id!r} also removed the unrelated target {kept_id!r}: "
        f"{_targets_for(aas, kept_id)!r}"
    )

    # The still-registered arm is the positive control: the scheduler did run in this window.
    moved = _poll_until(
        lambda: _read_capacity(ddb, kept_table),
        lambda cap: cap == 5,
        timeout_s=240,
        interval_s=5.0,
        description=(
            f"the scheduled action {action!r} firing at {fire_at.isoformat()} on the "
            f"still-registered table {kept_table!r} and dragging its read capacity to 5"
        ),
    )
    assert moved == 5, f"the kept table's read capacity settled at {moved!r}, expected 5"

    kept_acts = _activities(aas, kept_id)
    dispatch = [a for a in kept_acts if a["Cause"] == f"scheduled action name {action} was triggered"]
    assert len(dispatch) == 1, (
        f"the kept target recorded {len(dispatch)} dispatch activities for {action!r}, expected "
        f"exactly one: {[(a['Cause'], a['StatusMessage']) for a in kept_acts]!r}"
    )
    assert dispatch[0]["Description"] == "Setting min capacity to 5", (
        f"the dispatch activity described itself as {dispatch[0]['Description']!r}, expected "
        f"'Setting min capacity to 5'"
    )

    # Same instant, same action name, same table shape -- and no enforcement.
    assert _read_capacity(ddb, dropped_table) == 1, (
        f"the deregistered table's read capacity is "
        f"{_read_capacity(ddb, dropped_table)}, expected the 1 it was created with; the scheduled "
        f"action fired for the kept target in this same window, so a move here is enforcement "
        f"outliving the registration that authorised it"
    )
    assert _activities(aas, dropped_id) == [], (
        f"the deregistered target recorded scaling activities: "
        f"{_activities(aas, dropped_id)!r}; nothing was enforced, so nothing may be recorded"
    )
    assert _targets_for(aas, dropped_id) == [], (
        f"the deregistered target reappeared once its scheduled instant passed: "
        f"{_targets_for(aas, dropped_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
