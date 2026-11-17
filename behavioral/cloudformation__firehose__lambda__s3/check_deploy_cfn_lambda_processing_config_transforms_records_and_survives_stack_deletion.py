"""deploy-cfn-lambda-processing-config-transforms-records-and-survives-stack-deletion."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-processing-config-transforms-records-and-survives-stack-deletion"
GROUP = "deploy"
SERVICES = ["cloudformation", "firehose", "lambda", "s3"]

_STACK_CAP_S = 600.0
_STREAM_SETTLE_CAP_S = 180.0
_DELIVERY_CAP_S = 300.0
_GONE_CAP_S = 300.0
_POLL_S = 5.0

#: Appended by the processor function; only its real invocation can produce it.
_SUFFIX = b"-TRANSFORMED"

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
        "import base64\n\n"
        "def handler(event, context):\n"
        "    out = []\n"
        "    for record in event['records']:\n"
        "        payload = base64.b64decode(record['data'])\n"
        f"        transformed = base64.b64encode(payload + {_SUFFIX!r}).decode('utf-8')\n"
        "        out.append({'recordId': record['recordId'], 'result': 'Ok', 'data': transformed})\n"
        "    return {'records': out}\n"
    )


def _template(
    bucket: str,
    stream_name: str,
    function_name: str,
    buffer_interval_s: str,
    number_of_retries: str | None,
    tag_value: str,
) -> dict:
    owner_tag = [{"Key": "sim2real-owner", "Value": tag_value}]
    bucket_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"}
    bucket_objects_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"}
    function_arn = {"Fn::GetAtt": ["ProcessorFunction", "Arn"]}

    processor_parameters = [
        {"ParameterName": "LambdaArn", "ParameterValue": function_arn},
        {"ParameterName": "BufferIntervalInSeconds", "ParameterValue": buffer_interval_s},
        {"ParameterName": "BufferSizeInMBs", "ParameterValue": "1"},
    ]
    if number_of_retries is not None:
        processor_parameters.append(
            {"ParameterName": "NumberOfRetries", "ParameterValue": number_of_retries}
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
        "UPDATE_COMPLETE",
        "ROLLBACK_COMPLETE",
        "CREATE_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
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


def _wait_for_object_count(s3, bucket: str, expect: int, cap_s: float) -> list[str]:
    deadline = time.monotonic() + cap_s
    keys: list[str] = []
    while True:
        resp = s3.list_objects_v2(Bucket=bucket)
        keys = sorted(o["Key"] for o in resp.get("Contents", []))
        if len(keys) >= expect:
            return keys
        if time.monotonic() > deadline:
            raise AssertionError(
                f"expected >= {expect} delivered object(s) in {bucket}, found {keys!r} after {cap_s}s"
            )
        time.sleep(_POLL_S)


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
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation-declared Lambda processing configuration on a Firehose S3 destination
    is applied, actually transforms delivered records, keeps running through an in-place
    parameter update, and the transformed data outlives the stack that produced it.
    """
    cfn = ctx.client("cloudformation")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    lambda_ = ctx.client("lambda")
    logs = ctx.client("logs")

    bucket = ctx.unique_name("sim2real-behav-fhlp-bkt-").lower()
    stream_name = ctx.unique_name("sim2real-behav-fhlp-ds-")
    function_name = ctx.unique_name("sim2real-behav-fhlp-fn-")
    stack_name = ctx.unique_name("sim2real-behav-fhlp-stack-")
    tag_value = ctx.unique_name("team-")

    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown_bucket(s3, bucket))

    ctx.on_cleanup(_reap_log_group(logs, f"/aws/lambda/{function_name}"))
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            _template(bucket, stream_name, function_name, "60", None, tag_value)
        ),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_teardown_stack_if_present(cfn, stack_name))

    status = _wait_for_stack_terminal(cfn, stack_name)
    if status != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED")
        ]
        raise AssertionError(f"stack {stack_name} ended in {status!r}: {reasons!r}")

    desc = _wait_stream_active(firehose, stream_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected ACTIVE once CREATE_COMPLETE settled, got {desc['DeliveryStreamStatus']!r}"
    )
    created_at = desc["CreateTimestamp"]

    function_arn = lambda_.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    dest = desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    proc_cfg = dest["ProcessingConfiguration"]
    assert proc_cfg["Enabled"] is True, f"expected processing enabled, read back {proc_cfg!r}"
    processors = proc_cfg["Processors"]
    assert len(processors) == 1 and processors[0]["Type"] == "Lambda", (
        f"expected a single Lambda processor, read back {processors!r}"
    )
    params = {p["ParameterName"]: p["ParameterValue"] for p in processors[0]["Parameters"]}
    assert params.get("LambdaArn") == function_arn, (
        f"template's processor function {function_arn!r} not reflected, read back {params.get('LambdaArn')!r}"
    )
    assert params.get("BufferIntervalInSeconds") == "60", (
        f"expected BufferIntervalInSeconds '60', read back {params.get('BufferIntervalInSeconds')!r}"
    )
    assert params.get("BufferSizeInMBs") == "1", (
        f"expected BufferSizeInMBs '1', read back {params.get('BufferSizeInMBs')!r}"
    )
    assert params.get("NumberOfRetries") == "3", (
        f"expected Firehose's documented default of '3' retries when the template sets none, "
        f"read back {params.get('NumberOfRetries')!r}"
    )

    record_1 = b"firehose-record-one"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": record_1})
    keys_1 = _wait_for_object_count(s3, bucket, expect=1, cap_s=_DELIVERY_CAP_S)
    assert len(keys_1) == 1, f"expected exactly 1 delivered object, found {keys_1!r}"
    body_1 = s3.get_object(Bucket=bucket, Key=keys_1[0])["Body"].read()
    assert body_1 == record_1 + _SUFFIX, (
        f"delivered object held {body_1!r}, expected the processor's transform {record_1 + _SUFFIX!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            _template(bucket, stream_name, function_name, "60", "2", tag_value)
        ),
        Capabilities=["CAPABILITY_IAM"],
    )
    update_status = _wait_for_stack_terminal(cfn, stack_name)
    assert update_status == "UPDATE_COMPLETE", f"update ended in {update_status!r}"

    desc_after = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]
    assert desc_after["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected ACTIVE after the in-place update, got {desc_after['DeliveryStreamStatus']!r}"
    )
    assert desc_after["CreateTimestamp"] == created_at, (
        "the delivery stream's creation time changed, meaning the update replaced it instead of "
        f"updating it in place: before {created_at!r}, after {desc_after['CreateTimestamp']!r}"
    )
    dest_after = desc_after["Destinations"][0]["ExtendedS3DestinationDescription"]
    params_after = {
        p["ParameterName"]: p["ParameterValue"]
        for p in dest_after["ProcessingConfiguration"]["Processors"][0]["Parameters"]
    }
    assert params_after.get("NumberOfRetries") == "2", (
        f"expected the updated NumberOfRetries '2' to read back, got {params_after.get('NumberOfRetries')!r}"
    )

    record_2 = b"firehose-record-two"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": record_2})
    keys_2 = _wait_for_object_count(s3, bucket, expect=2, cap_s=_DELIVERY_CAP_S)
    assert len(keys_2) == 2, f"expected exactly 2 delivered objects after the update, found {keys_2!r}"
    new_key = (set(keys_2) - set(keys_1)).pop()
    body_2 = s3.get_object(Bucket=bucket, Key=new_key)["Body"].read()
    assert body_2 == record_2 + _SUFFIX, (
        f"post-update delivery held {body_2!r}, expected the processor's transform {record_2 + _SUFFIX!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(cfn, stack_name)

    _STREAM_GONE = (
        "ResourceNotFoundException",
        f"Firehose under account {ctx.account} not found.",
    )
    expect_error(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name), *_STREAM_GONE
    )

    _FUNCTION_GONE = ("ResourceNotFoundException", f"Function not found: {function_arn}")
    expect_error(lambda: lambda_.get_function(FunctionName=function_name), *_FUNCTION_GONE)

    expected_bodies = {keys_1[0]: record_1 + _SUFFIX, new_key: record_2 + _SUFFIX}
    final_keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", []))
    assert final_keys == keys_2, (
        "stack deletion changed the bucket it never owned; expected the two delivered objects to "
        f"remain untouched, found {final_keys!r} instead of {keys_2!r}"
    )
    for key in keys_2:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert body == expected_bodies[key], (
            f"object {key} changed after stack deletion: now {body!r}, expected {expected_bodies[key]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
