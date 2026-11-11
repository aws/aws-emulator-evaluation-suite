"""confirm-product-instance-wrong-code-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-product-instance-wrong-code-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmProductInstance answers AuthFailure "Not authorised for product code <code>" for both a made-up code
    and AWS's documented example code on an account owning neither, and attaches nothing to the instance.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-cpi-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    def _describe_state() -> str:
        # DescribeInstances is eventually consistent immediately after RunInstances and can
        # transiently 404 on an instance id it just handed back; treat that as "not visible yet"
        # rather than a poll failure, so the bounded retry below is the thing that decides timeout.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
                "Instances"
            ][0]["State"]["Name"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return "not-visible-yet"
            raise

    _poll_until(
        _describe_state,
        lambda state: state in ("pending", "running"),
        timeout_s=60,
    )

    # Sanity: this fresh AMI-launched instance has no product codes attached.
    before = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="productCodes"
    )["ProductCodes"]
    assert before == [], f"expected no product codes on a fresh instance, got {before!r}"

    # Made-up product code: the caller owns no product code at all, so it is not
    # authorised to confirm ANY code -- AuthFailure, with a message naming this specific code.
    fabricated_code = "zzInvalidCode0000000000000"
    fab_error = _error_detail(
        lambda: ec2.confirm_product_instance(InstanceId=instance_id, ProductCode=fabricated_code)
    )
    assert fab_error["Code"] == "AuthFailure", (
        f"expected AuthFailure for an unowned, fabricated product code, got {fab_error!r}"
    )
    assert fab_error["Message"] == f"Not authorised for product code {fabricated_code}", (
        f"expected the AuthFailure message to name the fabricated code, got {fab_error!r}"
    )

    # AWS's own documented ConfirmProductInstance example code: syntactically valid and
    # long-published, but the caller owns it no more than the fabricated one above -- the
    # SAME AuthFailure, proving the rejection tracks account entitlement, not code format.
    published_code = "774F4FF8"
    pub_error = _error_detail(
        lambda: ec2.confirm_product_instance(InstanceId=instance_id, ProductCode=published_code)
    )
    assert pub_error["Code"] == "AuthFailure", (
        f"expected AuthFailure for a well-formed but unowned product code, got {pub_error!r}"
    )
    assert pub_error["Message"] == f"Not authorised for product code {published_code}", (
        f"expected the AuthFailure message to name the published code, got {pub_error!r}"
    )

    # Effect absence: neither rejected call attached anything to the instance.
    after = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="productCodes"
    )["ProductCodes"]
    assert after == [], f"expected no product codes attached after the rejected calls, got {after!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_detail(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
