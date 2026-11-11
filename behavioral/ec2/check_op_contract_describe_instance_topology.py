"""op-contract-describeInstanceTopology."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceTopology"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTopology omits a running t3.micro, which is not topology-eligible, and a
    well-formed never-issued instance ID, returning an empty list instead of an error; DryRun answers
    DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    instance_id = _launch_probe_instance(ctx, ec2, ami_id)

    def instance_state():
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
        return reservations[0]["Instances"][0]["State"]["Name"]

    _poll_until(
        instance_state,
        lambda state: state in ("running", "pending") and state is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )

    resp = ec2.describe_instance_topology(InstanceIds=[instance_id])
    assert "Instances" in resp, "response missing 'Instances' list"
    instances = resp["Instances"]
    assert isinstance(instances, list)
    # A t3.micro is not topology-eligible and is omitted from the list entirely, not listed with empty
    # NetworkNodes.
    assert instances == [], f"expected no topology entries for a non-eligible instance type, got {instances}"

    # A well-formed never-issued instance ID is filtered out silently here, without the
    # InvalidInstanceID.NotFound that DescribeInstances raises.
    unissued_id = "i-0000000000000dead"
    unissued_resp = ec2.describe_instance_topology(InstanceIds=[unissued_id])
    assert unissued_resp["Instances"] == [], (
        f"expected no topology entries for a never-issued id, got {unissued_resp['Instances']}"
    )

    code, message = _error(lambda: ec2.describe_instance_topology(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


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
