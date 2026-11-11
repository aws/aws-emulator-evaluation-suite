"""lambda-invoke-writes-log-stream-events-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invoke-writes-log-stream-events-positive"
GROUP = "log-delivery"
SERVICES = ["cloudwatch", "lambda", "logs"]

_CODE_MARKER = """
def lambda_handler(event, context):
    print(event["marker"])
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda invocation writes START/END/REPORT and the handler's own line to one log stream."""
    role_name, role_arn = _create_role(ctx, managed_policy_arns=[
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ])
    fn_name, fn_arn = _create_function(ctx, role_arn, _make_zip(_CODE_MARKER))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group_name))

    lam = ctx.client("lambda")
    marker = ctx.unique_name("marker-")
    resp = lam.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"marker": marker}).encode(),
    )
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"invoke raised a function error: {resp.get('FunctionError')!r}"
    request_id = resp["ResponseMetadata"].get("RequestId")
    assert request_id, "Invoke response carries no request id (x-amzn-RequestId)"

    events = _wait_log_events(
        ctx, log_group_name, timeout_s=_GONE_S, min_events=4,
        has=lambda ms: any(m.startswith(f"START RequestId: {request_id}") for m in ms),
    )
    assert events, f"no log stream of {log_group_name} ever held this invocation's START line"
    messages = [e["message"] for e in events]
    joined = "\n".join(messages)[:250]
    assert any(m.startswith("START RequestId:") for m in messages), joined
    assert any(m.startswith(f"END RequestId: {request_id}") for m in messages), joined
    assert any(m.startswith(f"REPORT RequestId: {request_id}") for m in messages), joined
    # the handler's own line lands in the same stream as this request id's START line
    assert any(m.strip() == marker for m in messages), f"marker line not in the START stream: {joined}"

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_lambda(ctx, fn_name, fn_arn)
    _gone_role(ctx, role_name)
    _gone_log_group(ctx, log_group_name)


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policies:
        for pname, pdoc in inline_policies.items():
            iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(pdoc))

    def _cleanup():
        for arn in managed_policy_arns:
            _tolerant(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=arn), "NoSuchEntity")()
        for pname in inline_policies or ():
            _tolerant(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=pname), "NoSuchEntity")()
        _tolerant(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")()

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


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
        Tags={"sim2real": CHECK},
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
    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"))
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


def _wait_log_events(ctx, log_group_name, timeout_s=90, min_events=1, stream_prefix=None, has=None):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
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
            if len(events) >= min_events and (has is None or has([e["message"] for e in events])):
                return events
        time.sleep(3)
    return []


def _delete_log_group_quiet(ctx, log_group_name):
    logs = ctx.client("logs")
    _tolerant(lambda: logs.delete_log_group(logGroupName=log_group_name), "ResourceNotFoundException")()


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_lambda(ctx, name: str, arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}",
                  f"Function not found: {arn}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}",
             f"Function not found: {arn}:$LATEST")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    missing = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", missing)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", missing,
    )


def _gone_log_group(ctx, name: str) -> None:
    logs = ctx.client("logs")
    logs.delete_log_group(logGroupName=name)
    nf = ("ResourceNotFoundException",)
    missing = "The specified log group does not exist."
    _poll_refused(lambda: logs.describe_log_streams(logGroupName=name), nf, 400, f"DescribeLogStreams {name}",
                  missing)
    listed = {g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])}
    assert name not in listed, f"DescribeLogGroups still lists deleted log group {name}"
    _refused(
        lambda: logs.put_log_events(logGroupName=name, logStreamName="gone",
                                    logEvents=[{"timestamp": int(time.time() * 1000), "message": "gone"}]),
        nf, 400, f"PutLogEvents {name}", missing,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
