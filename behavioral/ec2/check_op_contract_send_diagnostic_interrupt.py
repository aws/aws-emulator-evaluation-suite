"""op-contract-send-diagnostic-interrupt."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-send-diagnostic-interrupt"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendDiagnosticInterrupt returns 200 on a running Nitro instance, which stays running; a
    never-issued instance id fails with InvalidInstanceID.Malformed and its exact message."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_instance(ctx)

    # success path: diagnostic interrupt on a running Nitro-based (t3) instance succeeds;
    # the response has no output members beyond ResponseMetadata on real EC2 (no
    # "Return" field), so the effect is verified via the instance remaining
    # describable/running afterward.
    resp = ec2.send_diagnostic_interrupt(InstanceId=instance_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, status

    post_state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]["State"]["Name"],
        lambda s: s in ("running", "stopping", "stopped", "shutting-down", "terminated"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert post_state == "running", post_state

    # error boundary: an id EC2 could never have issued is rejected as Malformed before any
    # lookup. A non-zero leading hex digit on the real id keeps the length/charset but leaves
    # the range, and never names another live instance.
    bogus_id = _mutate_leading_hex_char(instance_id)
    code, message = _error(lambda: ec2.send_diagnostic_interrupt(InstanceId=bogus_id))
    assert code == "InvalidInstanceID.Malformed", code
    assert message == f"The instance ID '{bogus_id}' is malformed", message


def _mutate_leading_hex_char(resource_id: str) -> str:
    prefix, _, suffix = resource_id.partition("-")
    rotated = "e" if suffix[0] == "f" else "f"
    return f"{prefix}-{rotated}{suffix[1:]}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
