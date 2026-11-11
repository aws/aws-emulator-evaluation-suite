"""op-contract-describe-instance-credit-specifications."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-instance-credit-specifications"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceCreditSpecifications reports the real CPU-credit option of a
    burstable-performance instance explicitly launched as 'unlimited', and DryRun
    short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")
    ami_id = _find_al2023_ami(ctx)
    instance_id = _launch_instance(
        ctx,
        ami_id,
        instance_type="t3.micro",
        extra_kwargs={"CreditSpecification": {"CpuCredits": "unlimited"}},
    )

    spec = _poll_until(
        lambda: ec2.describe_instance_credit_specifications(InstanceIds=[instance_id])[
            "InstanceCreditSpecifications"
        ],
        lambda specs: bool(specs),
        timeout_s=30.0,
        interval_s=2.0,
    )[0]
    assert spec["InstanceId"] == instance_id, f"expected {instance_id}, got {spec['InstanceId']}"
    assert spec["CpuCredits"] == "unlimited", f"expected 'unlimited', got {spec['CpuCredits']}"

    # Default (no filter) listing must include this unlimited-credit instance. The unfiltered
    # listing can lag slightly behind the filtered, single-instance lookup above, so poll for it.
    default_listing = _poll_until(
        lambda: [
            s
            for page in ec2.get_paginator("describe_instance_credit_specifications").paginate()
            for s in page["InstanceCreditSpecifications"]
        ],
        lambda specs: any(s["InstanceId"] == instance_id for s in specs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert any(s["InstanceId"] == instance_id for s in default_listing), (
        f"instance {instance_id} not present in default (unfiltered) "
        "describe_instance_credit_specifications listing"
    )

    # Error boundary: DryRun short-circuits before the listing is performed.
    code, message = _error(lambda: ec2.describe_instance_credit_specifications(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _find_al2023_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx, ami_id: str, instance_type: str = "t3.micro", extra_kwargs: dict | None = None) -> str:
    ec2 = ctx.client("ec2")
    kwargs: dict[str, Any] = dict(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ec2-")}],
            }
        ],
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("VPCIdNotSpecified", "MissingInput"):
            raise AssertionError(f"cannot launch instance: {code}")
        raise

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
