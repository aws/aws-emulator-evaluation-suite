"""op-contract-modify-instance-network-performance-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-instance-network-performance-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceNetworkPerformanceOptions requires a stopped instance and rejects an invalid value."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_bandwidth_weighting_instance(ctx, ec2)

    # error boundary: ModifyInstanceNetworkPerformanceOptions requires the instance to be
    # stopped; real AWS rejects the call on a running instance.
    running_code, running_message = _error(
        lambda: ec2.modify_instance_network_performance_options(InstanceId=instance_id, BandwidthWeighting="vpc-1")
    )
    assert running_code == "InvalidState", f"expected InvalidState while running, got {running_code}"
    assert running_message == f"The instance '{instance_id}' is not in an allowed state: stopped", running_message
    unset = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
        "NetworkPerformanceOptions", {}
    )
    assert unset.get("BandwidthWeighting") in (None, "default"), f"weighting changed despite rejected call: {unset}"

    # restore leg: stopping the instance lets the identical call succeed.
    ec2.stop_instances(InstanceIds=[instance_id])
    stopped_state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
            "Name"
        ],
        lambda s: s == "stopped",
        timeout_s=180,
        interval_s=5,
    )
    assert stopped_state == "stopped", f"instance never reached stopped state (last: {stopped_state})"

    # success path
    resp = ec2.modify_instance_network_performance_options(InstanceId=instance_id, BandwidthWeighting="vpc-1")
    assert resp["BandwidthWeighting"] == "vpc-1", f"expected vpc-1, got {resp['BandwidthWeighting']}"
    assert resp["InstanceId"] == instance_id, f"expected {instance_id}, got {resp['InstanceId']}"

    described = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
            "NetworkPerformanceOptions", {}
        ),
        lambda o: o.get("BandwidthWeighting") == "vpc-1",
        timeout_s=60,
        interval_s=3,
    )
    assert described.get("BandwidthWeighting") == "vpc-1", "BandwidthWeighting never reflected in DescribeInstances"

    # error boundary: value outside the default|vpc-1|ebs-1 enum
    code, message = _error(
        lambda: ec2.modify_instance_network_performance_options(
            InstanceId=instance_id, BandwidthWeighting="not-a-real-weighting"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "\"not-a-real-weighting\" is not a valid value for bandwidth weighting. Specify a valid value and try again.", message


# ===== helpers =====


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


def _launch_bandwidth_weighting_instance(ctx, ec2) -> str:
    from botocore.exceptions import ClientError

    ami_id = _latest_al2023_ami(ec2)
    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    name = ctx.unique_name("sim2real-behav-")
    instance_type = "m8i.large"
    try:
        resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("InsufficientInstanceCapacity", "Unsupported", "InvalidParameterValue"):
            raise AssertionError(f"instance type {instance_type} unavailable in this account/region: {code}")
        raise
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
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
            f"instance {instance_id} never reached running state (last state: {state})",
        )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
