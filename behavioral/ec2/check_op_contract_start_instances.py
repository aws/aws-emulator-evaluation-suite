"""op-contract-start-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-start-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInstances moves a stopped instance to running; starting a terminated instance is
    rejected with IncorrectInstanceState and its message, and the instance stays terminated."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_instance(ctx)

    ec2.stop_instances(InstanceIds=[instance_id])
    _wait_instance_state(ctx, instance_id, {"stopped"})

    resp = ec2.start_instances(InstanceIds=[instance_id])
    change = resp["StartingInstances"][0]
    assert change["PreviousState"]["Name"] == "stopped", change["PreviousState"]["Name"]
    assert change["CurrentState"]["Name"] in ("pending", "running"), change["CurrentState"]["Name"]
    _wait_instance_state(ctx, instance_id, {"running"})

    ec2.terminate_instances(InstanceIds=[instance_id])
    _wait_instance_state(ctx, instance_id, {"terminated"})

    code, message = _error(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    assert code == "IncorrectInstanceState", f"expected IncorrectInstanceState, got {code!r}"
    assert message == (
        f"The instance '{instance_id}' is not in a state from which it can be started."
    ), f"unexpected IncorrectInstanceState message {message!r}"

    still = ec2.describe_instances(InstanceIds=[instance_id])
    final_state = still["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert final_state == "terminated", (
        f"rejected StartInstances must not move state off terminated, got {final_state!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


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
                # Eventual consistency right after launch or terminate; keep polling.
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
