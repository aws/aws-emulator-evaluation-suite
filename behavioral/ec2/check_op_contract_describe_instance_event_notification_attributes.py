"""op-contract-describe-instance-event-notification-attributes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-instance-event-notification-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-event-notification-attributes")
def run(ctx) -> None:
    """DescribeInstanceEventNotificationAttributes reflects the real, current set of
    registered tag keys, and DryRun short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")
    tag_key = ctx.unique_name("sim2real-event-tag-")

    baseline = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    baseline_keys = set(baseline.get("InstanceTagKeys", []))
    baseline_include_all = baseline["IncludeAllTagsOfInstance"]
    assert tag_key not in baseline_keys

    ec2.register_instance_event_notification_attributes(
        InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
    )
    ctx.on_cleanup(
        lambda: ec2.deregister_instance_event_notification_attributes(
            InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
        )
    )

    after = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    assert tag_key in after.get("InstanceTagKeys", []), (
        f"expected {tag_key} to be registered, got {after}"
    )
    assert after["IncludeAllTagsOfInstance"] == baseline_include_all, (
        "registering discrete InstanceTagKeys must not change IncludeAllTagsOfInstance: "
        f"was {baseline_include_all}, now {after['IncludeAllTagsOfInstance']}"
    )

    # Error boundary: DryRun short-circuits before the describe is performed.
    code, message = _error(lambda: ec2.describe_instance_event_notification_attributes(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
