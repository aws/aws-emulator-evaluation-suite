"""arbitrary-code-executes."""

from __future__ import annotations

import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "arbitrary-code-executes"
GROUP = 'compute'
SERVICES = ['lambda']
#: The default service-class budget for a poll; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = _BASIC_EXEC.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    """Delete the function URL, the function and its log group; only an already-gone resource
    (ResourceNotFoundException) is tolerated."""
    for delete in (
        lambda: lam.delete_function_url_config(FunctionName=name),
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, **kwargs, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deploy a novel function and verify it computes the correct output."""
    lam = ctx.client("lambda")
    code = """\
import hashlib, json
def handler(event, context):
    data = json.dumps(event, sort_keys=True).encode()
    return {"sha256": hashlib.sha256(data).hexdigest(), "keys": sorted(event.keys())}
"""
    fn = _deploy_function(ctx, lam, code)
    for payload in ({"foo": 1, "bar": 2}, {"z": "last", "a": "first", "m": "mid"}):
        resp = _invoke_sync(lam, fn, payload)
        expected_sha256 = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        expected_keys = sorted(payload.keys())
        assert resp["sha256"] == expected_sha256, (
            f"payload={payload!r} expected sha256={expected_sha256} got {resp['sha256']!r}"
        )
        assert resp["keys"] == expected_keys, (
            f"payload={payload!r} expected keys={expected_keys} got {resp['keys']!r}"
        )

    conf = lam.get_function(FunctionName=fn)["Configuration"]
    want_arn = f"arn:{_partition(ctx)}:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    assert conf["FunctionArn"] == want_arn, f"expected FunctionArn {want_arn!r}, got {conf['FunctionArn']!r}"
    assert conf["State"] == "Active", f"expected State Active, got {conf['State']!r}"

    lam.delete_function(FunctionName=fn)
    gone = ("ResourceNotFoundException", f"Function not found: {want_arn}")
    # Gone beat 1: GetFunction answers ResourceNotFoundException.
    got = _refusal(_error(lambda: lam.get_function(FunctionName=fn)), 404)
    assert got == gone, f"GetFunction on the deleted function: expected {gone}, got {got!r}"
    # Gone beat 2: the paginated listing no longer contains it.
    names = [f["FunctionName"] for page in lam.get_paginator("list_functions").paginate() for f in page["Functions"]]
    assert fn not in names, "deleted function still listed by ListFunctions"
    # Gone beat 3: invoking the dead function is refused. Invoke resolves the unqualified name to
    # $LATEST, so its not-found message names the qualified ARN, unlike GetFunction's. Invoke also
    # keeps reaching a just-deleted function for a while on AWS, so a success is retried until the
    # refusal arrives.
    gone_invoke = ("ResourceNotFoundException", f"Function not found: {want_arn}:$LATEST")
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.invoke(FunctionName=fn, Payload=b"{}")
        except ClientError as exc:
            got = _refusal(exc.response, 404)
            assert got == gone_invoke, f"Invoke on the deleted function: expected {gone_invoke}, got {got!r}"
            break
        assert time.monotonic() < deadline, "Invoke of the deleted function still succeeds after 120s"
        time.sleep(5)


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _refusal(resp, status):
    """(code, message) of a refusal, after grading its HTTP status class."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx for {err.get('Code')!r}, got {got_status!r}"
    )
    return err.get("Code"), err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
