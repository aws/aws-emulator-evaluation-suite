"""deploy-s3-bucket-policy-missing-policydocument-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-bucket-policy-missing-policydocument-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_SID = "sim2real-control"


def _template(bucket_name: str, *, with_document: bool) -> str:
    policy: dict = {"Bucket": {"Ref": "Bucket"}}
    if with_document:
        policy["PolicyDocument"] = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": _SID, "Effect": "Deny", "Principal": "*",
                "Action": "s3:GetBucketLogging", "Resource": {"Fn::GetAtt": ["Bucket", "Arn"]},
            }],
        }
    return json.dumps({
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
            "Policy": {"Type": "AWS::S3::BucketPolicy", "Properties": policy},
        }
    })


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::S3::BucketPolicy with no PolicyDocument fails pre-deployment property validation and
    creates no bucket, while the same template with a PolicyDocument deploys and attaches it.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    # Positive control: the identical template with a PolicyDocument, through CloudFormation.
    control_bucket = ctx.unique_name("sim2real-behav-bktpol-ctrl-")
    control_stack = ctx.unique_name("sim2real-behav-bktpol-ctrl-stack-")
    cfn.create_stack(StackName=control_stack, TemplateBody=_template(control_bucket, with_document=True),
                     Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_stack))
    status = _wait_terminal(cfn, control_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    got_control = json.loads(s3.get_bucket_policy(Bucket=control_bucket)["Policy"])
    assert [st.get("Sid") for st in got_control["Statement"]] == [_SID], (
        f"the control stack's bucket policy reads back as {got_control!r}"
    )

    # The one thing broken: the same template without a PolicyDocument.
    bucket_name = ctx.unique_name("sim2real-behav-bktpol-bad-")
    stack_name = ctx.unique_name("sim2real-behav-bktpol-bad-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(bucket_name, with_document=False),
                     Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == stack_name and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert stack_failed_reasons == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {stack_failed_reasons!r}"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "Policy", "AWS::S3::BucketPolicy", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Required property [PolicyDocument] not found", "/Resources/Policy/Properties",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )
    got = _error(lambda: s3.head_bucket(Bucket=bucket_name))
    assert got == ("404", "Not Found"), f"HeadBucket on the rejected stack's bucket name: {got!r}"

    for name in (stack_name, control_stack):
        _delete_stack(cfn, name)
        got = _error(lambda name=name: cfn.describe_stacks(StackName=name))
        assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"DescribeStacks after the delete of {name}: {got!r}"
        )
    got = _error(lambda: s3.get_bucket_policy(Bucket=control_bucket))
    assert got == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"the control stack's bucket after its stack delete: {got!r}"
    )


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
