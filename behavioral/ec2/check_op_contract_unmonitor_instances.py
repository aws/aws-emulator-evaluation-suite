"""op-contract-unmonitor-instances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-unmonitor-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnmonitorInstances disables detailed monitoring on a running instance and the state settles
    to disabled; a well-formed instance id never issued is rejected as InvalidInstanceID.NotFound."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_instance(ctx, Monitoring={"Enabled": True})

    _poll_until(
        lambda: _monitoring_state(ctx, instance_id),
        lambda s: s in ("enabled", "pending"),
        timeout_s=60.0,
    )

    resp = ec2.unmonitor_instances(InstanceIds=[instance_id])
    change = resp["InstanceMonitorings"][0]
    assert change["InstanceId"] == instance_id, change
    assert change["Monitoring"]["State"] in ("disabling", "disabled"), change

    final_state = _poll_until(
        lambda: _monitoring_state(ctx, instance_id), lambda s: s == "disabled", timeout_s=120.0
    )
    assert final_state == "disabled", final_state

    # A well-formed instance id that was never issued.
    bogus_id = "i-0000000000000dead"
    code, message = _error_code(lambda: ec2.unmonitor_instances(InstanceIds=[bogus_id]))
    assert code == "InvalidInstanceID.NotFound", f"bogus={bogus_id} code={code} message={message!r}"
    assert message == f"The instance ID '{bogus_id}' does not exist", message


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
                # Eventual consistency right after a state change; keep polling.
                return None
            raise
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s)


def _monitoring_state(ctx, instance_id):
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            # Eventual consistency right after a state change; the caller retries.
            return None
        raise
    return resp["Reservations"][0]["Instances"][0]["Monitoring"]["State"]


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
