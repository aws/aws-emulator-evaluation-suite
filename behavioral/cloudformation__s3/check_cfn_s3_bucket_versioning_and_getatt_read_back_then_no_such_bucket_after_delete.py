"""cfn-s3-bucket-versioning-and-getatt-read-back-then-no-such-bucket-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-versioning-and-getatt-read-back-then-no-such-bucket-after-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "s3"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks by stack id until a terminal status; return it.

    The stack id (ARN), unlike the bare name, keeps resolving through
    DELETE_COMPLETE, so this one loop serves both the create and the delete wait.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::S3::Bucket is real at S3: its versioning matches S3's own
    answer, its Arn and domain-name Fn::GetAtt values are the ones the name and region define, and
    deleting the stack removes the bucket from S3, not just from CFN."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-behav-cfn-s3bkt-")
    bucket = ctx.unique_name("sim2real-behav-cfn-s3bkt-").lower()[:63]

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket,
                    "VersioningConfiguration": {"Status": "Enabled"},
                },
            },
        },
        "Outputs": {
            "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
            "DomainName": {"Value": {"Fn::GetAtt": ["Bucket", "DomainName"]}},
            "RegionalDomainName": {"Value": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]}},
            "DualStackDomainName": {"Value": {"Fn::GetAtt": ["Bucket", "DualStackDomainName"]}},
        },
    })

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    created = _wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    physical_id = _physical_id(cfn, stack_id, "Bucket")
    assert physical_id == bucket, f"expected physical id {bucket!r}, got {physical_id!r}"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert sorted(outputs) == ["BucketArn", "DomainName", "DualStackDomainName", "RegionalDomainName"], (
        f"stack outputs {sorted(outputs)!r}, expected the four GetAtt outputs")
    assert outputs["BucketArn"] == f"arn:aws:s3:::{bucket}", f"GetAtt Arn {outputs['BucketArn']!r}"
    # The domain-name attributes are host names whose first label is the bucket; the regional and
    # dual-stack ones also name the stack's region, and the three are distinct.
    names = {k: outputs[k] for k in ("DomainName", "RegionalDomainName", "DualStackDomainName")}
    for key, host in names.items():
        assert host.split(".", 1)[0] == bucket and "/" not in host and ":" not in host, (
            f"GetAtt {key} {host!r} is not a host name whose first label is the bucket {bucket!r}")
    for key in ("RegionalDomainName", "DualStackDomainName"):
        assert ctx.region in names[key].split("."), (
            f"GetAtt {key} {names[key]!r} does not name the stack's region {ctx.region!r}")
    assert len(set(names.values())) == 3, f"GetAtt domain names are not distinct: {names!r}"
    # Independent read at the destination: S3's own VersioningConfiguration must
    # carry the property the template declared.
    versioning = s3.get_bucket_versioning(Bucket=bucket)
    assert versioning.get("Status") == "Enabled", (
        f"expected S3 get_bucket_versioning Status 'Enabled', got {versioning.get('Status')!r}"
    )

    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack(cfn, stack_id)
    assert deleted == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {deleted!r}"

    code, message = _wait_bucket_gone(s3, bucket)
    assert code == "NoSuchBucket", f"expected NoSuchBucket after stack delete, got {code!r}"
    assert message == "The specified bucket does not exist", (
        f"expected the standard NoSuchBucket message, got {message!r}"
    )


def _wait_bucket_gone(s3, bucket: str, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll a GET call (which, unlike HEAD, carries a body with Code and Message)
    on *bucket* until it reports gone; the physical delete may lag DELETE_COMPLETE."""
    deadline = time.monotonic() + timeout_s
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            s3.get_bucket_versioning(Bucket=bucket)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"]["Message"]
            if last_code == "NoSuchBucket":
                return last_code, last_message
        else:
            last_code, last_message = None, None
        time.sleep(interval_s)
    raise AssertionError(
        f"bucket {bucket!r} still answering after {timeout_s}s of polling "
        f"(last_code={last_code!r}, last_message={last_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
