"""delete-rule-removes-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rule-removes-it"
GROUP = 'rule'
SERVICES = ['events']

def _cleanup_rule(client, name, bus):
    """Remove any attached targets, then delete the rule (delete_rule refuses a rule with targets)."""
    try:
        ids = [t["Id"] for t in client.list_targets_by_rule(Rule=name, EventBusName=bus).get("Targets", [])]
        if ids:
            client.remove_targets(Rule=name, Ids=ids, EventBusName=bus)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    client.delete_rule(Name=name, EventBusName=bus, Force=True)

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRule removes the rule: an independent describe reports NotFound, a
    mutation on the dead id is likewise refused, and the freed name is reusable
    for a brand-new rule."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(Name=rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    ev.delete_rule(Name=rule, EventBusName=bus)
    expected = ("ResourceNotFoundException", f"Rule {rule} does not exist on EventBus {bus}.")
    err = _error(lambda: ev.describe_rule(Name=rule, EventBusName=bus))
    assert err == expected, f"expected {expected} from DescribeRule on a deleted rule, got {err}"

    mutate_err = _error(lambda: ev.enable_rule(Name=rule, EventBusName=bus))
    assert mutate_err == expected, (
        f"expected {expected} from EnableRule on a deleted rule, got {mutate_err}"
    )

    ev.put_rule(Name=rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav.reused"]}')
    reused = ev.describe_rule(Name=rule, EventBusName=bus)
    assert reused["State"] == "ENABLED", f"expected the freed rule name to be reusable, got State={reused.get('State')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
