"""op-contract-disassociate-instance-event-window."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-instance-event-window"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateInstanceEventWindow removes a tag-based association target
    from an event window; DryRun reports DryRunOperation without changing state."""
    ec2 = ctx.client("ec2")

    tag_key = ctx.unique_name("sim2real-iew-")
    tag_value = "target"

    window_name = ctx.unique_name("sim2real-event-window-")
    window_id = ec2.create_instance_event_window(
        Name=window_name,
        TimeRanges=[{"StartWeekDay": "monday", "StartHour": 2, "EndWeekDay": "monday", "EndHour": 6}],
        TagSpecifications=[{"ResourceType": "instance-event-window", "Tags": [{"Key": "Name", "Value": window_name}]}],
    )["InstanceEventWindow"]["InstanceEventWindowId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id)))

    assoc_target = {"InstanceTags": [{"Key": tag_key, "Value": tag_value}]}
    assoc_resp = ec2.associate_instance_event_window(
        InstanceEventWindowId=window_id, AssociationTarget=assoc_target
    )
    tags_after_associate = assoc_resp["InstanceEventWindow"]["AssociationTarget"].get("Tags", [])
    assert any(t["Key"] == tag_key and t["Value"] == tag_value for t in tags_after_associate), assoc_resp

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _client_error(
        lambda: ec2.disassociate_instance_event_window(
            InstanceEventWindowId=window_id, AssociationTarget=assoc_target, DryRun=True
        )
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    described = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])["InstanceEventWindows"][0]
    still_tags = described["AssociationTarget"].get("Tags", [])
    assert any(t["Key"] == tag_key and t["Value"] == tag_value for t in still_tags), described

    resp = ec2.disassociate_instance_event_window(InstanceEventWindowId=window_id, AssociationTarget=assoc_target)
    tags_after_disassociate = resp["InstanceEventWindow"]["AssociationTarget"].get("Tags", [])
    assert not any(t["Key"] == tag_key for t in tags_after_disassociate), resp

    described_after = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
        "InstanceEventWindows"
    ][0]
    assert not any(
        t["Key"] == tag_key for t in described_after["AssociationTarget"].get("Tags", [])
    ), described_after


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceEventWindowIDNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
