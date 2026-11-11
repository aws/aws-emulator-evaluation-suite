"""op-contract-describeInstanceStatus."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceStatus"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceStatus reports the launched instance's status once it is
    tracked, and raises InvalidInstanceID.NotFound for a nonexistent instance."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    instance_id = _launch_probe_instance(ctx, ec2, ami_id)

    def probe():
        # Immediately after RunInstances, DescribeInstanceStatus can transiently
        # raise InvalidInstanceID.NotFound before the instance has fully
        # propagated; treat that as "not ready yet" and keep polling.
        try:
            resp = ec2.describe_instance_status(
                InstanceIds=[instance_id], IncludeAllInstances=True
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return []
            raise
        return resp.get("InstanceStatuses", [])

    items = _poll_until(probe, lambda v: len(v) == 1, timeout_s=90.0, interval_s=3.0)
    status = items[0]
    assert status["InstanceId"] == instance_id, (
        f"expected status for {instance_id}, got {status['InstanceId']}"
    )
    assert status["InstanceState"]["Name"] in ("pending", "running"), (
        f"expected pending/running, got {status['InstanceState']['Name']!r}"
    )

    # Real EC2 ids carry an internal structure: a single-digit rotation of a real id is
    # sometimes InvalidInstanceID.Malformed, and which positions are safe varies per id. Rotate
    # digit positions until real AWS confirms one is well-formed but absent.
    prefix, digits = instance_id[:2], instance_id[2:]
    code = message = fake_instance_id = None
    for i in range(len(digits)):
        fake_instance_id = prefix + digits[:i] + format((int(digits[i], 16) + 1) % 16, "x") + digits[i + 1:]
        code, message = _error_of(
            lambda c=fake_instance_id: ec2.describe_instance_status(InstanceIds=[c])
        )
        if code == "InvalidInstanceID.NotFound":
            break
        assert code == "InvalidInstanceID.Malformed", f"unexpected error code: {code}"
    assert code == "InvalidInstanceID.NotFound", f"unexpected error code: {code}"
    assert message == f"The instance ID '{fake_instance_id}' does not exist", message


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


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
