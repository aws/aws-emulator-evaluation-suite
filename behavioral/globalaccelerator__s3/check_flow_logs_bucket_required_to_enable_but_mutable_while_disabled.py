"""flow-logs-bucket-required-to-enable-but-mutable-while-disabled."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-logs-bucket-required-to-enable-but-mutable-while-disabled"
GROUP = "flow-logs"
SERVICES = ["globalaccelerator", "s3"]


def _error(fn):
    """Return the (code, message) fn() raised; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry(fn, codes, budget_s=600.0, delay_s=10.0):
    """Call fn() until it stops raising one of `codes`; re-raise anything else."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() > deadline:
                raise
            time.sleep(delay_s)


def _delete_accelerator_net(ga, arn):
    """Undo an accelerator completely: disable, then delete once the disable has settled."""
    try:
        ga.update_accelerator(AcceleratorArn=arn, Enabled=False)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AcceleratorNotFoundException":
            raise
        return
    _retry(
        lambda: ga.delete_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget_s=600.0,
    )


def _emptied_bucket(ctx):
    """A fresh, empty bucket in ctx.region; every version of every object is dropped before delete."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-gaflow-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _drop():
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_drop)
    return name


@tags("axis:rejection", "concern:negative-classes", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """UpdateAcceleratorAttributes refuses FlowLogsEnabled=true with no FlowLogsS3Bucket, leaving
    flow logs off; with a bucket the same call enables them, and once they are disabled again the
    bucket and prefix can be repointed at a second bucket while FlowLogsEnabled stays false.
    """
    ga = ctx.client("globalaccelerator")

    accelerator = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-gaflow-"),
        IpAddressType="IPV4",
        Enabled=True,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]
    arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(lambda: _delete_accelerator_net(ga, arn))

    # Enabling with no destination is refused, and the attributes stay at their off default.
    code, message = _error(
        lambda: ga.update_accelerator_attributes(AcceleratorArn=arn, FlowLogsEnabled=True)
    )
    assert code == "InvalidArgumentException", (
        f"UpdateAcceleratorAttributes(FlowLogsEnabled=True) with no bucket returned {code!r}, "
        f"expected 'InvalidArgumentException'"
    )
    assert message == "Flow logs s3 bucket should not be empty.", (
        f"UpdateAcceleratorAttributes(FlowLogsEnabled=True) with no bucket returned message "
        f"{message!r}"
    )
    unchanged = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert unchanged["FlowLogsEnabled"] is False, (
        f"the refused enable still turned flow logs on: FlowLogsEnabled={unchanged['FlowLogsEnabled']!r}"
    )

    # Positive control: the same call succeeds once a destination bucket is given.
    first_bucket = _emptied_bucket(ctx)
    enabled = ga.update_accelerator_attributes(
        AcceleratorArn=arn,
        FlowLogsEnabled=True,
        FlowLogsS3Bucket=first_bucket,
        FlowLogsS3Prefix="accelerator-flow-logs",
    )["AcceleratorAttributes"]
    assert enabled["FlowLogsEnabled"] is True, (
        f"enabling with a destination bucket left FlowLogsEnabled={enabled['FlowLogsEnabled']!r}"
    )
    assert enabled["FlowLogsS3Bucket"] == first_bucket, (
        f"enabling read back FlowLogsS3Bucket={enabled['FlowLogsS3Bucket']!r}, expected {first_bucket!r}"
    )
    on_read = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert on_read["FlowLogsEnabled"] is True and on_read["FlowLogsS3Bucket"] == first_bucket, (
        f"an independent DescribeAcceleratorAttributes read back {on_read!r}, expected flow logs "
        f"on and pointed at {first_bucket!r}"
    )

    # Disable, confirmed by an independent read.
    ga.update_accelerator_attributes(AcceleratorArn=arn, FlowLogsEnabled=False)
    disabled = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert disabled["FlowLogsEnabled"] is False, (
        f"after disabling, DescribeAcceleratorAttributes reports FlowLogsEnabled={disabled['FlowLogsEnabled']!r}"
    )

    # While disabled, the bucket and prefix can be repointed at a second bucket without
    # turning flow logs back on.
    second_bucket = _emptied_bucket(ctx)
    repointed = ga.update_accelerator_attributes(
        AcceleratorArn=arn,
        FlowLogsEnabled=False,
        FlowLogsS3Bucket=second_bucket,
        FlowLogsS3Prefix="accelerator-flow-logs-2",
    )["AcceleratorAttributes"]
    assert repointed["FlowLogsEnabled"] is False, (
        f"repointing the bucket while disabled turned flow logs on: "
        f"FlowLogsEnabled={repointed['FlowLogsEnabled']!r}"
    )
    assert repointed["FlowLogsS3Bucket"] == second_bucket, (
        f"repointing while disabled read back FlowLogsS3Bucket={repointed['FlowLogsS3Bucket']!r}, "
        f"expected {second_bucket!r}"
    )
    assert repointed["FlowLogsS3Prefix"] == "accelerator-flow-logs-2", (
        f"repointing while disabled read back FlowLogsS3Prefix={repointed['FlowLogsS3Prefix']!r}"
    )
    final_read = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert final_read["FlowLogsS3Bucket"] == second_bucket and final_read["FlowLogsEnabled"] is False, (
        f"an independent read after the repoint returned {final_read!r}, expected the second "
        f"bucket with flow logs still off"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
