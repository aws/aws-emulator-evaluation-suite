"""op-contract-describeInstances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstances returns a launched instance's ID, AMI, type and pending or running state, and a
    well-formed never-issued instance ID fails with InvalidInstanceID.Malformed and its exact message
    instead of an empty result."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    instance_id = _launch_probe_instance(ctx, ec2, ami_id)

    def probe():
        # Immediately after RunInstances, DescribeInstances can transiently
        # raise InvalidInstanceID.NotFound before the instance has fully
        # propagated; treat that as "not ready yet" and keep polling.
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return None
            raise
        reservations = resp.get("Reservations", [])
        if not reservations:
            return None
        return reservations[0]["Instances"][0]

    instance = _poll_until(probe, lambda v: v is not None, timeout_s=60.0, interval_s=2.0)
    assert instance["InstanceId"] == instance_id, (
        f"expected DescribeInstances to reflect {instance_id}, got {instance['InstanceId']}"
    )
    assert instance["ImageId"] == ami_id, (
        f"expected ImageId {ami_id}, got {instance['ImageId']}"
    )
    assert instance["InstanceType"] == "t3.micro", (
        f"expected InstanceType t3.micro, got {instance['InstanceType']}"
    )
    assert instance["State"]["Name"] in ("pending", "running"), (
        f"expected state pending or running, got {instance['State']['Name']}"
    )

    # An id EC2 could never have issued fails with InvalidInstanceID.Malformed before the existence
    # lookup, not NotFound and not an empty result: the real id with a non-zero leading hex digit
    # keeps the shape but leaves the range.
    lead = "e" if instance_id[2] == "f" else "f"
    candidate = f"i-{lead}{instance_id[3:]}"
    code, message = _error(lambda: ec2.describe_instances(InstanceIds=[candidate]))
    assert code == "InvalidInstanceID.Malformed", (
        f"expected a syntactically-valid but nonexistent instance id to be rejected as "
        f"Malformed, got {code!r}"
    )
    assert message == (
        f'Invalid id: "{candidate}"'
    ), f"unexpected InvalidInstanceID.Malformed message: {message!r}"


def _latest_al2023_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:

        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    return images[0]["ImageId"]


def _launch_probe_instance(ctx, ec2, ami_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-ec2-")
    try:
        resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
            ],
            SubnetId=ctx.network().subnet_ids[0],
        )
    except ClientError as exc:

        raise AssertionError(f"cannot launch probe instance: {exc.response['Error']['Code']}")
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
