"""op-contract-register-instance-event-notification-attributes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-register-instance-event-notification-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-event-notification-attributes")
def run(ctx) -> None:
    """RegisterInstanceEventNotificationAttributes adds a tag key to the
    account/region scheduled-event-notification allow-list, and DryRun is
    honored as a pure permission-check boundary."""
    ec2 = ctx.client("ec2")
    tag_key = ctx.unique_name("sim2real-evtnotif-")

    # --- success path: register a tag key, confirm it shows up ---
    resp = ec2.register_instance_event_notification_attributes(
        InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
    )
    ctx.on_cleanup(
        lambda: ec2.deregister_instance_event_notification_attributes(
            InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
        )
    )
    registered_keys = resp["InstanceTagAttribute"].get("InstanceTagKeys", [])
    assert tag_key in registered_keys, f"{tag_key} missing from register response: {registered_keys}"

    describe = ec2.describe_instance_event_notification_attributes()
    described_keys = describe["InstanceTagAttribute"].get("InstanceTagKeys", [])
    assert tag_key in described_keys, "registered tag key not reflected in describe"

    # --- error boundary: DryRun must short-circuit with DryRunOperation ---
    dry_run_tag_key = ctx.unique_name("sim2real-evtnotif-dry-")
    code, message = _error(
        lambda: ec2.register_instance_event_notification_attributes(
            DryRun=True,
            InstanceTagAttribute={"InstanceTagKeys": [dry_run_tag_key]},
        )
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    # DryRun must not have actually registered the key -- confirm via an
    # independent read that the permission-check boundary is pure.
    after_dry_run = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    after_dry_run_keys = after_dry_run.get("InstanceTagKeys", [])
    assert dry_run_tag_key not in after_dry_run_keys, (
        f"DryRun must not mutate state, but {dry_run_tag_key} appeared in {after_dry_run_keys}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
