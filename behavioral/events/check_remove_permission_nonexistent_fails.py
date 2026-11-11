"""remove-permission-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-nonexistent-fails"
GROUP = 'permission'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: RemovePermission for a StatementId that was never granted must fail,
    without disturbing an unrelated granted statement, and must succeed once that same
    StatementId is actually granted."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-behav", "Value": bus}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))

    control_id = "granted-control"
    ev.put_permission(
        EventBusName=bus,
        Action="events:PutEvents",
        Principal="111122223333",
        StatementId=control_id,
    )
    policy = ev.describe_event_bus(Name=bus).get("Policy") or ""
    assert control_id in policy, f"expected positive control statement in policy, got: {policy}"

    absent_id = "never-granted"
    try:
        result = ev.remove_permission(EventBusName=bus, StatementId=absent_id)
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"RemovePermission for a never-granted StatementId SUCCEEDED: {result!r}")
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = "Statement with the provided id does not exist."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    policy_after = ev.describe_event_bus(Name=bus).get("Policy") or ""
    assert control_id in policy_after, (
        f"failed RemovePermission on {absent_id!r} must not disturb an unrelated granted "
        f"statement, got policy: {policy_after}"
    )
    assert absent_id not in policy_after, (
        f"StatementId {absent_id!r} must not appear in a policy it was never granted in, "
        f"got: {policy_after}"
    )

    # restore: grant the previously-nonexistent statement, then the identical call must succeed
    ev.put_permission(
        EventBusName=bus,
        Action="events:PutEvents",
        Principal="111122223333",
        StatementId=absent_id,
    )
    policy_granted = ev.describe_event_bus(Name=bus).get("Policy") or ""
    assert absent_id in policy_granted, f"expected restored statement in policy, got: {policy_granted}"

    ev.remove_permission(EventBusName=bus, StatementId=absent_id)
    policy_final = ev.describe_event_bus(Name=bus).get("Policy") or ""
    assert absent_id not in policy_final, (
        f"identical RemovePermission call must now succeed once the statement exists, "
        f"got policy: {policy_final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
