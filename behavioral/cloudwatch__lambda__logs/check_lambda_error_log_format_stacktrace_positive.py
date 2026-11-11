"""lambda-error-log-format-stacktrace-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-error-log-format-stacktrace-positive"
GROUP = "data-format"
SERVICES = ["cloudwatch", "lambda", "logs"]

_CODE_RAISES = """
def lambda_handler(event, context):
    raise ValueError("boom-behavioral-test")
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unhandled exception in Lambda code is captured with stack-trace formatting
    in the CloudWatch Logs stream."""
    role_arn = _create_role(ctx, managed_policy_arns=[
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ])
    fn_name, _ = _create_function(ctx, role_arn, _make_zip(_CODE_RAISES))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group_name))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert resp.get("FunctionError") == "Unhandled", f"expected FunctionError Unhandled, got {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())
    assert payload.get("errorType") == "ValueError", f"expected errorType ValueError, got {payload.get('errorType')!r}"
    assert payload.get("errorMessage") == "boom-behavioral-test", f"expected errorMessage boom-behavioral-test, got {payload.get('errorMessage')!r}"

    events = _wait_log_events(
        ctx,
        log_group_name,
        timeout_s=90,
        # wait for the actual REPORT line, not a proxy event count: the count a real
        # invocation produces varies with how the runtime batches the traceback write,
        # so a fixed min_events risks returning before REPORT has landed.
        predicate=lambda msgs: any(m.startswith("REPORT RequestId:") for m in msgs),
    )
    assert events, f"no log events ever appeared in {log_group_name}"
    joined = "\n".join(e["message"] for e in events)
    assert "boom-behavioral-test" in joined, joined
    assert "Traceback (most recent call last)" in joined, joined
    assert "ValueError" in joined, joined
    # the REPORT line must still show up even though the invocation errored
    assert any(m.startswith("REPORT RequestId:") for m in (e["message"] for e in events)), joined


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _create_function(ctx, role_arn, zip_bytes, handler="lambda_function.lambda_handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real:managed": "true"},
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


def _wait_log_events(ctx, log_group_name, timeout_s=90, predicate=None, stream_prefix=None):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_events = []
    while time.monotonic() < deadline:
        try:
            streams = logs.describe_log_streams(
                logGroupName=log_group_name, orderBy="LastEventTime", descending=True
            )["logStreams"]
        except logs.exceptions.ResourceNotFoundException:
            streams = []
        for st in streams:
            if stream_prefix and not st["logStreamName"].startswith(stream_prefix):
                continue
            events = logs.get_log_events(
                logGroupName=log_group_name, logStreamName=st["logStreamName"], startFromHead=True
            )["events"]
            if events:
                last_events = events
            if predicate(e["message"] for e in events):
                return events
        time.sleep(3)
    return last_events


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
