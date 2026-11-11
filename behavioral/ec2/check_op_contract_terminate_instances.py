"""op-contract-terminate-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-terminate-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateInstances reports PreviousState running and CurrentState shutting-down or terminated;
    an instance id EC2 never issues fails with InvalidInstanceID.Malformed."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_instance(ctx)

    # success path
    resp = ec2.terminate_instances(InstanceIds=[instance_id])
    change = resp["TerminatingInstances"][0]
    assert change["PreviousState"]["Name"] == "running", (
        f"expected PreviousState running, got {change['PreviousState']['Name']}"
    )
    assert change["CurrentState"]["Name"] in ("shutting-down", "terminated"), (
        f"expected an immediate shutting-down/terminated transition, got {change['CurrentState']['Name']}"
    )
    _wait_instance_state(ctx, instance_id, {"terminated"})

    # error boundary: an id EC2 could never have issued is rejected as Malformed before the
    # existence lookup. A non-zero leading hex digit on the real id keeps the length/charset valid
    # but leaves the range, and never names another live instance.
    code = _error_code(
        lambda: ec2.terminate_instances(InstanceIds=[_mutate_leading_hex_char(instance_id)])
    )
    assert code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed for a never-issued instance id, got {code}"
    )


def _mutate_leading_hex_char(resource_id: str) -> str:
    prefix, _, suffix = resource_id.partition("-")
    rotated = "e" if suffix[0] == "f" else "f"
    return f"{prefix}-{rotated}{suffix[1:]}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {resp!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, "no al2023 AMIs found"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _wait_instance_state(ctx, instance_id, states, timeout_s=300.0):
    ec2 = ctx.client("ec2")

    def probe():
        from botocore.exceptions import ClientError

        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                # transient eventual-consistency gap right after a state change;
                # keep polling instead of failing outright.
                return None
            raise
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s)


def _launch_instance(ctx, instance_type="t3.micro", **kwargs):
    ec2 = ctx.client("ec2")
    ami = _latest_al2023_ami(ctx)
    resp = ec2.run_instances(
        ImageId=ami,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-inst-")}],
            }
        ],
        **kwargs,
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_instance_state(ctx, instance_id, {"running"})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
