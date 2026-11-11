"""lambda-custom-boto3-logs-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-custom-boto3-logs-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]

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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler's PutLogEvents to a custom log group its role is not granted fails with
    AccessDeniedException and writes nothing; granting that log group to the same role makes the
    identical invoke succeed and the message appear."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # --- broken: execution role's own-log permission does NOT cover the custom log group ---
    bad_log_group = ctx.unique_name("/sim2real-behav/custom-bad-")
    logs.create_log_group(logGroupName=bad_log_group)
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, bad_log_group))
    bad_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{bad_log_group}:*"

    bad_fn_name = ctx.unique_name("sim2real-behav-fn-")
    bad_fn_log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:/aws/lambda/{bad_fn_name}:*"
    bad_role_arn, bad_role_name = _create_role(ctx, inline_policies={
        "own-log-access-only": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": bad_fn_log_group_arn,
            }],
        }
    })
    bad_stream = ctx.unique_name("stream-")
    bad_message = f"custom-log-message-{uuid.uuid4()}"
    bad_fn_name, _ = _create_function(
        ctx, bad_role_arn, _make_zip(_CODE_CUSTOM_LOGS),
        env={"CUSTOM_LOG_GROUP": bad_log_group, "CUSTOM_LOG_STREAM": bad_stream, "CUSTOM_MESSAGE": bad_message},
        fn_name=bad_fn_name,
    )
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, f"/aws/lambda/{bad_fn_name}"))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=bad_fn_name, InvocationType="RequestResponse")
    payload = json.loads(resp["Payload"].read())
    assert payload.get("ok") is False, f"handler unexpectedly reported success: {payload}"
    assert payload.get("error_code") == "AccessDeniedException", payload

    events = _wait_stream_events(ctx, bad_log_group, bad_stream, timeout_s=30, min_events=1)
    assert not events, f"custom log group unexpectedly received events despite missing permission: {events}"

    # --- restore: grant the SAME role access to the SAME custom log group, then replay the
    #     IDENTICAL invocation and demand it now succeeds (proving this
    #     specific broken thing is now fixed rather than that some other setup works) ---
    restore_policy_name = "custom-log-access-restored"
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": bad_group_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(ctx, bad_role_name, restore_policy_name))

    restored_payload = _invoke_until_ok(ctx, bad_fn_name, timeout_s=90)
    assert restored_payload.get("ok") is True, f"role still denied after restoring permission: {restored_payload}"

    restored_events = _wait_stream_events(ctx, bad_log_group, bad_stream, timeout_s=60, min_events=1)
    assert restored_events and any(e["message"] == bad_message for e in restored_events), restored_events


def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })


def _create_role(ctx, managed_policy_arns=(), inline_policies=None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy())
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
    return role_arn, role_name


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


def _delete_role_policy_quiet(ctx, role_name, policy_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _invoke_until_ok(ctx, fn_name, timeout_s=90):
    """Re-drive the identical invocation, tolerating only the transient AccessDeniedException
    an IAM policy grant needs to propagate before Lambda's assumed-role session sees it."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_payload = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
        last_payload = json.loads(resp["Payload"].read())
        if last_payload.get("ok") is True:
            return last_payload
        if last_payload.get("error_code") != "AccessDeniedException":
            raise AssertionError(f"unexpected error after restoring permission: {last_payload}")
        time.sleep(3)
    raise AssertionError(f"role still denied after restoring permission within {timeout_s}s: {last_payload}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
