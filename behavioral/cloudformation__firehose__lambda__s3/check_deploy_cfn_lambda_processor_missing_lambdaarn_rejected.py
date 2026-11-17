"""deploy-cfn-lambda-processor-missing-lambdaarn-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-processor-missing-lambdaarn-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "firehose", "lambda", "s3"]

_STACK_CAP_S = 600.0
_STREAM_SETTLE_CAP_S = 180.0
_POLL_S = 5.0

def _error(fn) -> tuple[str, str]:
    """The ``(Code, Message)`` ``fn`` raises. An unexpected success raises too, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code: str, message: str) -> None:
    got_code, got_message = _error(fn)
    assert (got_code, got_message) == (code, message), (
        f"expected ({code!r}, {message!r}), got ({got_code!r}, {got_message!r})"
    )


def _processor_source() -> str:
    return (
        "def handler(event, context):\n"
        "    out = [{'recordId': r['recordId'], 'result': 'Ok', 'data': r['data']}"
        " for r in event['records']]\n"
        "    return {'records': out}\n"
    )


def _template(
    bucket: str, stream_name: str, function_name: str, tag_value: str, *, include_lambda_arn: bool
) -> dict:
    owner_tag = [{"Key": "sim2real-owner", "Value": tag_value}]
    bucket_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"}
    bucket_objects_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"}
    function_arn = {"Fn::GetAtt": ["ProcessorFunction", "Arn"]}

    processor_parameters = [
        {"ParameterName": "BufferIntervalInSeconds", "ParameterValue": "60"},
        {"ParameterName": "BufferSizeInMBs", "ParameterValue": "1"},
    ]
    if include_lambda_arn:
        processor_parameters.insert(
            0, {"ParameterName": "LambdaArn", "ParameterValue": function_arn}
        )

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ProcessorRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Tags": owner_tag,
                },
            },
            "ProcessorFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ProcessorRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": _processor_source()},
                    "Tags": owner_tag,
                },
            },
            "FirehoseRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "firehose.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "firehose-s3-and-lambda-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:AbortMultipartUpload",
                                            "s3:GetBucketLocation",
                                            "s3:GetObject",
                                            "s3:ListBucket",
                                            "s3:ListBucketMultipartUploads",
                                            "s3:PutObject",
                                        ],
                                        "Resource": [bucket_arn, bucket_objects_arn],
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "lambda:InvokeFunction",
                                            "lambda:GetFunctionConfiguration",
                                        ],
                                        "Resource": [function_arn],
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": owner_tag,
                },
            },
            "DeliveryStream": {
                "Type": "AWS::KinesisFirehose::DeliveryStream",
                "DependsOn": ["FirehoseRole", "ProcessorFunction"],
                "Properties": {
                    "DeliveryStreamName": stream_name,
                    "DeliveryStreamType": "DirectPut",
                    "ExtendedS3DestinationConfiguration": {
                        "BucketARN": bucket_arn,
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                        "ProcessingConfiguration": {
                            "Enabled": True,
                            "Processors": [{"Type": "Lambda", "Parameters": processor_parameters}],
                        },
                    },
                    "Tags": owner_tag,
                },
            },
        },
    }


def _wait_for_stack_terminal(cfn, stack_name: str, cap_s: float = _STACK_CAP_S) -> str:
    terminal = {
        "CREATE_COMPLETE",
        "ROLLBACK_COMPLETE",
        "CREATE_FAILED",
    }
    deadline = time.monotonic() + cap_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} did not reach a terminal state in {cap_s}s")
        time.sleep(_POLL_S)


def _wait_for_stack_deleted(cfn, stack_name: str, cap_s: float = _STACK_CAP_S) -> None:
    deadline = time.monotonic() + cap_s
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} was not deleted within {cap_s}s")
        time.sleep(_POLL_S)


def _wait_stream_active(firehose, stream_name: str, cap_s: float = _STREAM_SETTLE_CAP_S) -> dict:
    """Poll past CREATING; a CREATE_COMPLETE stack can report this before the stream settles."""
    deadline = time.monotonic() + cap_s
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] != "CREATING":
            return desc
        if time.monotonic() > deadline:
            raise AssertionError(f"stream {stream_name} still CREATING after {cap_s}s")
        time.sleep(_POLL_S)


def _delivery_stream_failure_reason(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if event["LogicalResourceId"] == "DeliveryStream" and event.get("ResourceStatus", "").endswith(
            "FAILED"
        ):
            return event.get("ResourceStatusReason", "")
    raise AssertionError(f"no failed DeliveryStream event found in stack {stack_name}'s events")


#: The resource handler wraps the service exception's str() and its own HandlerErrorCode; the
#: Request ID, Extended Request ID and RequestToken segments vary per call, so only the message
#: and the handler code are parsed out and compared.
_REASON_RE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*?) \(Service: Firehose, '
    r"Status Code: \d+, Request ID: [0-9a-f-]+, Extended Request ID: \S+\) "
    r'\(SDK Attempt Count: \d+\)" \(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<handler_code>\w+)\)$'
)


def _parse_delivery_stream_rejection(reason: str) -> tuple[str, str]:
    match = _REASON_RE.match(reason)
    assert match, f"stack event reason did not match the CFN/Firehose wrapper shape: {reason!r}"
    return match.group("handler_code"), match.group("message")


def _teardown_bucket(s3, bucket: str):
    def undo() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                objs = page.get("Contents", [])
                if objs:
                    errors = s3.delete_objects(
                        Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                    ).get("Errors")
                    if errors:
                        raise RuntimeError(f"DeleteObjects left {len(errors)} object(s): {errors[:3]!r}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    return undo


def _teardown_stack_if_present(cfn, stack_name: str):
    def undo() -> None:
        try:
            cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        cfn.delete_stack(StackName=stack_name)
        _wait_for_stack_deleted(cfn, stack_name)

    return undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0):
    def undo() -> None:
        deadline = time.monotonic() + budget_s
        absent = 0
        while absent < reads:
            groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
            if any(g["logGroupName"] == name for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=name)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < reads:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
                time.sleep(interval_s)

    return undo


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-declared Lambda processor with no LambdaArn parameter is rejected at
    delivery-stream creation, and the stream is never created; the same template with the
    parameter present succeeds.
    """
    cfn = ctx.client("cloudformation")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    lambda_ = ctx.client("lambda")
    logs = ctx.client("logs")

    bucket = ctx.unique_name("sim2real-behav-fhpn-bkt-").lower()
    tag_value = ctx.unique_name("team-")

    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown_bucket(s3, bucket))

    # Positive control: the identical shape, with LambdaArn present, deploys cleanly.
    good_stream = ctx.unique_name("sim2real-behav-fhpn-ds-good-")
    good_function = ctx.unique_name("sim2real-behav-fhpn-fn-good-")
    good_stack = ctx.unique_name("sim2real-behav-fhpn-stack-good-")

    ctx.on_cleanup(_reap_log_group(logs, f"/aws/lambda/{good_function}"))
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=json.dumps(
            _template(bucket, good_stream, good_function, tag_value, include_lambda_arn=True)
        ),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_teardown_stack_if_present(cfn, good_stack))

    good_status = _wait_for_stack_terminal(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", f"positive control stack ended in {good_status!r}"
    good_desc = _wait_stream_active(firehose, good_stream)
    assert good_desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"positive control expected ACTIVE, got {good_desc['DeliveryStreamStatus']!r}"
    )

    cfn.delete_stack(StackName=good_stack)
    _wait_for_stack_deleted(cfn, good_stack)
    _GOOD_GONE = ("ResourceNotFoundException", f"Firehose under account {ctx.account} not found.")
    expect_error(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=good_stream), *_GOOD_GONE
    )

    # Negative: break exactly one thing — the processor never names the function to invoke.
    bad_stream = ctx.unique_name("sim2real-behav-fhpn-ds-bad-")
    bad_function = ctx.unique_name("sim2real-behav-fhpn-fn-bad-")
    bad_stack = ctx.unique_name("sim2real-behav-fhpn-stack-bad-")

    ctx.on_cleanup(_reap_log_group(logs, f"/aws/lambda/{bad_function}"))
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=json.dumps(
            _template(bucket, bad_stream, bad_function, tag_value, include_lambda_arn=False)
        ),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_teardown_stack_if_present(cfn, bad_stack))

    bad_status = _wait_for_stack_terminal(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"expected the missing-LambdaArn stack to roll back, ended in {bad_status!r}"
    )

    reason = _delivery_stream_failure_reason(cfn, bad_stack)
    handler_code, message = _parse_delivery_stream_rejection(reason)
    assert handler_code == "InvalidRequest", (
        f"expected CloudFormation's HandlerErrorCode 'InvalidRequest', got {handler_code!r}"
    )
    assert message == "LambdaArn is required when Lambda processor is used.", (
        f"expected the exact Firehose rejection message, got {message!r}"
    )

    _BAD_GONE = ("ResourceNotFoundException", f"Firehose under account {ctx.account} not found.")
    expect_error(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream), *_BAD_GONE
    )

    cfn.delete_stack(StackName=bad_stack)
    _wait_for_stack_deleted(cfn, bad_stack)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
