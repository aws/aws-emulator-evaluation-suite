"""diagnostic-interrupt-graviton-processor-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "diagnostic-interrupt-graviton-processor-rejected"
GROUP = "instance-lifecycle"
SERVICES = ["ec2"]


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, so
    acceptance never reads as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ec2, arch: str) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": [f"al2023-ami-*-{arch}"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, f"no al2023 AMIs found for architecture {arch!r}"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _subnet_for_type(ctx, instance_type: str) -> str:
    """A subnet of the shared network whose Availability Zone offers ``instance_type``."""
    ec2 = ctx.client("ec2")
    net = ctx.network()
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = [az for az in net.availability_zones if az in offered and az in net.subnets]
    assert usable, (
        f"no Availability Zone in the shared network offers {instance_type!r}; "
        f"offered={sorted(offered)!r}"
    )
    return net.subnets[usable[0]]


def _launch(ctx, instance_type: str, arch: str) -> str:
    ec2 = ctx.client("ec2")
    ami = _latest_al2023_ami(ec2, arch)
    subnet_id = _subnet_for_type(ctx, instance_type)
    resp = ec2.run_instances(
        ImageId=ami,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-dint-")}],
            }
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(lambda: _instance_state(ec2, instance_id), lambda s: s == "running")
    return instance_id


def _instance_state(ec2, instance_id: str):
    """The instance's State.Name, or None during the brief eventual-consistency gap right
    after RunInstances where DescribeInstances has not caught up yet."""
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None
        raise
    return resp["Reservations"][0]["Instances"][0]["State"]["Name"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendDiagnosticInterrupt succeeds on a Nitro x86_64 instance but is refused on a
    Graviton (Nitro arm64) instance, which is the legal neighbour the x86_64 case controls for;
    neither instance's running state changes.
    """
    ec2 = ctx.client("ec2")

    control_id = _launch(ctx, "t3.micro", "x86_64")
    resp = ec2.send_diagnostic_interrupt(InstanceId=control_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 sending a diagnostic interrupt to a Nitro x86_64 instance, "
        f"got {resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    control_state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[control_id])["Reservations"][0]["Instances"][0][
            "State"
        ]["Name"],
        lambda s: s in ("running", "stopping", "stopped", "shutting-down", "terminated"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert control_state == "running", (
        f"expected the x86_64 instance to stay running after the interrupt, got {control_state!r}"
    )

    graviton_id = _launch(ctx, "t4g.micro", "arm64")
    code, message = _error(lambda: ec2.send_diagnostic_interrupt(InstanceId=graviton_id))
    assert code == "UnsupportedOperation", (
        f"expected UnsupportedOperation sending a diagnostic interrupt to a Graviton "
        f"instance, got {code!r} ({message!r})"
    )
    assert message == "This instance type does not support diagnostic interrupts.", (
        f"unexpected UnsupportedOperation message: {message!r}"
    )
    graviton_state = ec2.describe_instances(InstanceIds=[graviton_id])["Reservations"][0]["Instances"][
        0
    ]["State"]["Name"]
    assert graviton_state == "running", (
        f"a refused diagnostic interrupt must leave the Graviton instance running, "
        f"got {graviton_state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
