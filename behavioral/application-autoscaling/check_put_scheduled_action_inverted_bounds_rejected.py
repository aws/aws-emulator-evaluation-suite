"""put-scheduled-action-inverted-bounds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-inverted-bounds-rejected"
GROUP = "scheduled-action-rejected"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"
# A one-shot cron far in the future: these actions are stored and graded, never dispatched.
_NEVER = "cron(0 0 1 1 ? 2035)"


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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """PutScheduledAction refuses MaxCapacity below MinCapacity and stores nothing, leaving the name
    free, while a valid action on the same target is stored and echoed back verbatim.
    """
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")
    table = _create_provisioned_table(ctx, ddb, read_cap=1, write_cap=1)
    resource_id = f"table/{table}"
    bad_action = ctx.unique_name("sim2real-aas-bad-")
    good_action = ctx.unique_name("sim2real-aas-good-")

    aas.register_scalable_target(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        MinCapacity=1,
        MaxCapacity=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    code, message = _error(
        aas.put_scheduled_action,
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        ScheduledActionName=bad_action,
        Schedule=_NEVER,
        Timezone="UTC",
        ScalableTargetAction={"MinCapacity": 8, "MaxCapacity": 3},
    )
    assert code == "ValidationException", (
        f"an inverted ScalableTargetAction (min 8, max 3) was rejected as {code!r}; real AWS "
        f"raises ValidationException"
    )
    assert message == "Maximum capacity cannot be less than minimum capacity", (
        f"the rejection message was {message!r}; real AWS names the inverted pair rather than "
        f"reporting a generic validation failure"
    )

    assert _scheduled_actions(aas, resource_id) == [], (
        f"the refused PutScheduledAction left a scheduled action behind on {resource_id!r}: "
        f"{_scheduled_actions(aas, resource_id)!r}; a rejected put must store nothing at all"
    )

    # Positive control: a valid action on the same target, at the same never-firing instant.
    aas.put_scheduled_action(
        ServiceNamespace=_NS,
        ResourceId=resource_id,
        ScalableDimension=_DIM,
        ScheduledActionName=good_action,
        Schedule=_NEVER,
        Timezone="UTC",
        ScalableTargetAction={"MinCapacity": 2, "MaxCapacity": 9},
    )
    ctx.on_cleanup(lambda: _delete_action(aas, resource_id, good_action))

    stored = _scheduled_actions(aas, resource_id)
    assert [a["ScheduledActionName"] for a in stored] == [good_action], (
        f"the target's scheduled actions are {[a['ScheduledActionName'] for a in stored]!r}; only "
        f"the valid action {good_action!r} may be stored, and the refused {bad_action!r} must be "
        f"absent"
    )
    assert stored[0]["ScalableTargetAction"] == {"MinCapacity": 2, "MaxCapacity": 9}, (
        f"the stored ScalableTargetAction was {stored[0]['ScalableTargetAction']!r}, expected the "
        f"submitted pair {{'MinCapacity': 2, 'MaxCapacity': 9}} echoed verbatim"
    )
    assert stored[0]["Schedule"] == _NEVER, (
        f"the stored Schedule was {stored[0]['Schedule']!r}, expected {_NEVER!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
