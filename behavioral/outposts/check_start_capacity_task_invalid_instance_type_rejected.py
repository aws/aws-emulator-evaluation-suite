"""start-capacity-task-invalid-instance-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-capacity-task-invalid-instance-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartCapacityTask with an InstanceType that does not match '<family>.<size>' fails with
    ValidationException and the exact pattern message and creates no capacity task, while "c5.xlarge" passes
    that validation and fails with a different ValidationException message.
    """
    outposts = ctx.client("outposts")
    tag = {"sim2real-check": CHECK}
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"), Tags=tag
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))
    outpost_id = outposts.create_outpost(
        Name=ctx.unique_name("sim2real-outposts-op-"),
        SiteId=site_id,
        AvailabilityZone=_pick_availability_zone(ctx),
        Tags=tag,
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: outposts.delete_outpost(OutpostId=outpost_id))

    code, message = _error(
        lambda: outposts.start_capacity_task(
            OutpostIdentifier=outpost_id,
            InstancePools=[{"InstanceType": "not_a_valid_instance_type", "Count": 1}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    assert message == (
        "1 validation error detected: Value at 'instancePools.1.member.instanceType' failed to "
        r"satisfy constraint: Member must satisfy regular expression pattern: ^[a-z0-9\-]+\.[a-z0-9\-]+$"
    ), f"unexpected malformed-InstanceType message: {message!r}"

    # Effect absent: no capacity task exists for this Outpost.
    tasks = outposts.list_capacity_tasks(OutpostIdentifierFilter=outpost_id).get("CapacityTasks", [])
    assert tasks == [], f"expected no capacity tasks for {outpost_id}, found {tasks!r}"

    # Positive control: a syntactically valid instance type clears format validation. On this
    # fresh, hardware-less Outpost the request is still rejected -- but with a DIFFERENT
    # ValidationException message (the Outpost is not ACTIVE, not a malformed format),
    # proving the first rejection was specifically about the malformed InstanceType string and
    # not a blanket rejection of StartCapacityTask.
    control_code, control_message = _error(
        lambda: outposts.start_capacity_task(
            OutpostIdentifier=outpost_id,
            InstancePools=[{"InstanceType": "c5.xlarge", "Count": 1}],
        )
    )
    assert control_code == "ValidationException", (
        f"expected the syntactically-valid instance type to clear format validation and fail "
        f"with a different ValidationException, got {control_code!r} ({control_message!r})"
    )
    assert control_message == (
        f"Failed to create capacity task for {outpost_id}. Outpost should have LifeCycleStatus "
        f"being ACTIVE, but {outpost_id} has LifeCycleStatus PENDING"
    ), f"unexpected control rejection message: {control_message!r}"
    assert control_message != message, (
        f"expected a different rejection message for the syntactically-valid instance type than "
        f"for the malformed one, both were {message!r}"
    )


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
