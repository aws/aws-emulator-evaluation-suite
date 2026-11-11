"""op-contract-modify-instance-placement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-instance-placement"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstancePlacement moves a stopped instance into a placement group and rejects the change while running."""
    ec2 = ctx.client("ec2")
    pg_name = ctx.unique_name("sim2real-behav-pg-")
    tag_spec = [{"ResourceType": "placement-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    # ModifyInstancePlacement rejects "cluster" strategy placement groups outright
    # (UnsupportedPlacementGroupStrategy), regardless of instance state -- moving
    # an instance into/out of a cluster placement group is only supported at
    # launch time. "spread" placement groups are supported by this API and are
    # still restricted to stopped instances, which is the behavior under test.
    pg = ec2.create_placement_group(GroupName=pg_name, Strategy="spread", TagSpecifications=tag_spec)[
        "PlacementGroup"
    ]
    pg_group_id = pg.get("GroupId")
    ctx.on_cleanup(lambda: _delete_placement_group(ec2, pg_name))

    instance_id = _launch_test_instance(ctx, ec2)

    # error boundary: host id / tenancy / placement group changes require a stopped instance
    code, message = _error(lambda: ec2.modify_instance_placement(InstanceId=instance_id, GroupName=pg_name))
    assert code == "InvalidInstanceState", f"expected InvalidInstanceState, got {code}"
    assert message == "Placement groups can only be changed for instances in the 'stopped' state.", message

    # the rejected call must not have taken effect -- an independent read, not the mutating
    # call's own response, confirms the instance still carries no placement group
    rejected_placement = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
        "Placement", {}
    )
    assert not rejected_placement.get("GroupName") and (
        pg_group_id is None or rejected_placement.get("GroupId") != pg_group_id
    ), f"rejected modify_instance_placement must not take effect, got placement {rejected_placement}"

    ec2.stop_instances(InstanceIds=[instance_id])
    state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
            "Name"
        ],
        lambda s: s == "stopped",
        timeout_s=180,
        interval_s=5,
    )
    if state != "stopped":
        raise AssertionError(
            f"instance {instance_id} never reached stopped state (last state: {state})"
        )

    # success path -- identical call, only the instance state differs
    resp = ec2.modify_instance_placement(InstanceId=instance_id, GroupName=pg_name)
    assert resp["Return"] is True, f"expected Return=True for the restored call, got {resp['Return']!r}"

    # describe_instances can lag briefly behind the modify call; poll until
    # the placement group assignment is visible. AWS may surface the
    # assignment via either GroupName or GroupId in the Placement struct.
    placement = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["Placement"],
        lambda p: p.get("GroupName") == pg_name or (pg_group_id is not None and p.get("GroupId") == pg_group_id),
        timeout_s=60,
        interval_s=3,
    )
    if not (
        placement.get("GroupName") == pg_name or (pg_group_id is not None and placement.get("GroupId") == pg_group_id)
    ):
        raise AssertionError(
            f"placement group assignment {pg_name!r} ({pg_group_id!r}) never became visible, got {placement}"
        )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            # newly-launched instances can briefly be unreadable via
            # DescribeInstances due to eventual consistency; keep polling.
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _default_subnet_id(ec2, *, ctx) -> str:
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a test instance")
    return subnets[0]["SubnetId"]


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 x86_64 AMI found")
    return sorted(images, key=lambda i: i["CreationDate"])[-1]["ImageId"]


def _launch_test_instance(ctx, ec2, instance_type="t3.micro") -> str:
    ami_id = _latest_al2023_ami(ec2)
    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    name = ctx.unique_name("sim2real-behav-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    # Wait for termination: the placement group cleanup registered earlier runs after this
    # one and is refused (InvalidPlacementGroup.InUse) while the instance is still shutting down.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
            "Name"
        ],
        lambda s: s == "running",
        timeout_s=180,
        interval_s=5,
    )
    if state != "running":
        raise AssertionError(
            f"instance {instance_id} never reached running state (last state: {state})"
        )
    return instance_id


def _terminate_and_wait(ec2, instance_id: str) -> None:
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _delete_placement_group(ec2, group_name: str, timeout_s: float = 180.0) -> None:
    """A placement group stays InUse for a while after its last instance terminates; retry until the delete lands."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_placement_group(GroupName=group_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidPlacementGroup.InUse" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
