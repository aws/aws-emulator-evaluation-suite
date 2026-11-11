"""deploy-s3-bucket-policy-lifecycle-then-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-bucket-policy-lifecycle-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::S3::BucketPolicy reads back through GetBucketPolicy verbatim;
    an update dropping it leaves the bucket with NoSuchBucketPolicy, and the stack delete removes
    the bucket (NoSuchBucket)."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-bktpol-")
    stack_name = ctx.unique_name("sim2real-behav-bktpol-stack-")
    statement = {
        "Sid": "sim2real-deny-insecure-transport",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            {"Fn::GetAtt": ["Bucket", "Arn"]},
            {"Fn::Sub": "${Bucket.Arn}/*"},
        ],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    resources = {
        "Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": bucket_name},
        },
        "Policy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "Bucket"},
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]},
            },
        },
    }
    template = json.dumps({"Resources": resources})
    without_policy = json.dumps({"Resources": {"Bucket": resources["Bucket"]}})

    cfn.create_stack(StackName=stack_name, TemplateBody=template,
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    got = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
    assert len(got["Statement"]) == 1, f"expected exactly 1 statement, got {got['Statement']!r}"
    got_stmt = got["Statement"][0]
    expected_resources = {
        f"arn:aws:s3:::{bucket_name}",
        f"arn:aws:s3:::{bucket_name}/*",
    }
    assert got_stmt["Sid"] == statement["Sid"], f"Sid mismatch: {got_stmt!r}"
    assert got_stmt["Effect"] == "Deny", f"Effect mismatch: {got_stmt!r}"
    assert got_stmt["Action"] == "s3:*", f"Action mismatch: {got_stmt!r}"
    assert set(got_stmt["Resource"]) == expected_resources, (
        f"Resource mismatch: got {got_stmt['Resource']!r}, expected {expected_resources!r}"
    )
    assert got_stmt["Condition"] == statement["Condition"], f"Condition mismatch: {got_stmt!r}"

    # The policy's own removal, observed on the bucket that outlives it.
    cfn.update_stack(StackName=stack_name, TemplateBody=without_policy,
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    code, message = _error(lambda: s3.get_bucket_policy(Bucket=bucket_name))
    assert (code, message) == ("NoSuchBucketPolicy", "The bucket policy does not exist"), (
        f"GetBucketPolicy after the update removed the BucketPolicy: {(code, message)!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    code, message = _error(lambda: s3.get_bucket_policy(Bucket=bucket_name))
    assert code == "NoSuchBucket", f"expected NoSuchBucket after stack delete, got {code!r}"
    assert message == "The specified bucket does not exist", (
        f"unexpected not-found message: {message!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
