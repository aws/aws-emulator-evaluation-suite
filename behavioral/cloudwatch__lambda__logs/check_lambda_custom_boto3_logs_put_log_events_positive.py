"""lambda-custom-boto3-logs-put-log-events-positive."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-custom-boto3-logs-put-log-events-positive"
GROUP = "sdk-call"
SERVICES = ["cloudwatch", "lambda", "logs"]

_RESOURCE_TAGS = {"sim2real-check": CHECK}

_CODE_CUSTOM_LOGS = """
import os
import time
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    logs = boto3.client("logs")
    log_group = os.environ["CUSTOM_LOG_GROUP"]
    stream_name = os.environ["CUSTOM_LOG_STREAM"]
    message = os.environ["CUSTOM_MESSAGE"]
    try:
        try:
            logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                raise
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=stream_name,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
        )
        return {"ok": True}
    except ClientError as exc:
        return {"ok": False, "error_code": exc.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda handler using boto3 logs.put_log_events into a custom log group succeeds
    when the execution role has that specific logs permission."""
    logs = ctx.client("logs")
    custom_log_group = ctx.unique_name("/sim2real-behav/custom-")
    logs.create_log_group(logGroupName=custom_log_group, tags=_RESOURCE_TAGS)
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, custom_log_group))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    custom_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{custom_log_group}:*"

    # explicit function name so we can scope the role's OWN execution-log permission tightly
    # (avoids relying on the wildcard-Resource AWSLambdaBasicExecutionRole managed policy)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    fn_log_group = f"/aws/lambda/{fn_name}"
    fn_log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{fn_log_group}:*"

    role_arn = _create_role(
        ctx,
        inline_policies={
            "scoped-log-access": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": fn_log_group_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": custom_group_arn,
                    },
                ],
            }
        },
    )

    stream_name = ctx.unique_name("stream-")
    message = f"custom-log-message-{uuid.uuid4()}"
    fn_name, _ = _create_function(
        ctx,
        role_arn,
        _make_zip(_CODE_CUSTOM_LOGS),
        env={
            "CUSTOM_LOG_GROUP": custom_log_group,
            "CUSTOM_LOG_STREAM": stream_name,
            "CUSTOM_MESSAGE": message,
        },
        fn_name=fn_name,
    )
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, fn_log_group))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
    payload = json.loads(resp["Payload"].read())
    assert payload.get("ok") is True, f"handler reported failure: {payload}"

    events = _wait_stream_events(ctx, custom_log_group, stream_name, timeout_s=60, min_events=1)
    assert events, f"custom log group {custom_log_group}/{stream_name} never received events"
    assert any(e["message"] == message for e in events), [e["message"] for e in events]


def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })


def _create_role(ctx, managed_policy_arns=(), inline_policies=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policies:
        for pname, pdoc in inline_policies.items():
            iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(pdoc))

    def _cleanup():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policies:
            for pname in inline_policies:
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _make_zip(code: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function(ctx, role_arn, zip_bytes, handler="lambda_function.lambda_handler", env=None, timeout=30, fn_name=None):
    lam = ctx.client("lambda")
    fn_name = fn_name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=True,
        Tags=dict(_RESOURCE_TAGS),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 90
    last_exc = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_function_active(ctx, fn_name)
    return fn_name, resp["FunctionArn"]


def _wait_function_active(ctx, fn_name, timeout_s=90):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function never became Active (last state={state})")


def _wait_stream_events(ctx, log_group_name, stream_name, timeout_s=60, min_events=1):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events = logs.get_log_events(
                logGroupName=log_group_name, logStreamName=stream_name, startFromHead=True
            )["events"]
        except logs.exceptions.ResourceNotFoundException:
            events = []
        if len(events) >= min_events:
            return events
        time.sleep(3)
    return []


def _delete_log_group_quiet(ctx, log_group_name):
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
