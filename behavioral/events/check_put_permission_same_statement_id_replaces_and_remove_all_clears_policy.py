"""put-permission-same-statement-id-replaces-and-remove-all-clears-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-permission-same-statement-id-replaces-and-remove-all-clears-policy"
GROUP = "permission"
SERVICES = ["events"]

# Documentation account ids (AWS reserves 111122223333 / 444455556666 for examples); never ours.
_FIRST_PRINCIPAL = "111122223333"
_SECOND_PRINCIPAL = "444455556666"
_ORG_ID = "o-sim2realexample"  # well-formed but fictitious organization id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission with an existing StatementId replaces that statement; "*" and account
    principals and a Condition are stored as IAM policy forms on the bus ARN; RemoveAllPermissions
    drops the whole Policy and is idempotent.
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal="*", StatementId="sim2real-any")
    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal="*", StatementId="sim2real-org",
                          Condition={"Type": "StringEquals", "Key": "aws:PrincipalOrgID", "Value": _ORG_ID})
    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal=_FIRST_PRINCIPAL,
                          StatementId="sim2real-acct")
    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal=_SECOND_PRINCIPAL,
                          StatementId="sim2real-acct")

    statements = _statements(events, bus)
    assert sorted(statements) == ["sim2real-acct", "sim2real-any", "sim2real-org"], (
        f"re-granting an existing StatementId must replace it, not add one; Sids are {sorted(statements)!r}"
    )
    acct = statements["sim2real-acct"]
    assert acct["Principal"] == {"AWS": _SECOND_PRINCIPAL}, (
        f"the replaced statement must carry the second principal, got {acct['Principal']!r}"
    )
    anyone = statements["sim2real-any"]
    assert anyone["Principal"] == "*", f"a wildcard principal is stored as '*', got {anyone['Principal']!r}"
    org = statements["sim2real-org"]
    assert (org["Principal"], org.get("Condition")) == ("*", {"StringEquals": {"aws:PrincipalOrgID": _ORG_ID}}), (
        f"a Condition parameter is stored as an IAM condition block, got {(org['Principal'], org.get('Condition'))!r}"
    )
    assert "Condition" not in anyone, f"an unconditioned grant must carry no Condition, got {anyone.get('Condition')!r}"
    for sid, stmt in statements.items():
        assert (stmt["Effect"], stmt["Action"], stmt["Resource"]) == ("Allow", "events:PutEvents", bus_arn), (
            f"statement {sid!r} must Allow events:PutEvents on the bus ARN, got "
            f"{(stmt['Effect'], stmt['Action'], stmt['Resource'])!r}"
        )

    events.remove_permission(EventBusName=bus, RemoveAllPermissions=True)
    after = events.describe_event_bus(Name=bus)
    assert "Policy" not in after, f"RemoveAllPermissions must drop the policy entirely, got {after.get('Policy')!r}"

    events.remove_permission(EventBusName=bus, RemoveAllPermissions=True)
    assert "Policy" not in events.describe_event_bus(Name=bus), "a second RemoveAllPermissions must stay a no-op"

    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal=_FIRST_PRINCIPAL,
                          StatementId="sim2real-again")
    assert sorted(_statements(events, bus)) == ["sim2real-again"], (
        "a grant after remove-all must start a fresh policy holding only the new statement"
    )


def _statements(events, bus: str) -> dict:
    policy = json.loads(events.describe_event_bus(Name=bus)["Policy"])
    return {s["Sid"]: s for s in policy["Statement"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
