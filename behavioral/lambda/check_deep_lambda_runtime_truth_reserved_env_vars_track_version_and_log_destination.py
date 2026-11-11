"""deep-lambda-runtime-truth-reserved-env-vars-track-version-and-log-destination."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-reserved-env-vars-track-version-and-log-destination"
GROUP = "execution_environment"
SERVICES = ["lambda"]

_KEYS = (
    "AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_VERSION", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_LOG_GROUP_NAME", "AWS_LAMBDA_LOG_STREAM_NAME", "AWS_REGION",
    "AWS_LAMBDA_INITIALIZATION_TYPE", "_X_AMZN_TRACE_ID", "_HANDLER",
)

_PROBE = """\
import os

KEYS = %r


def handler(event, context):
    return {
        "env": {k: os.environ.get(k) for k in KEYS},
        "log_stream": context.log_stream_name,
        "log_group": context.log_group_name,
        "request_id": context.aws_request_id,
    }
""" % (_KEYS,)

_TRACE_RE = re.compile(r"(?:^|;)Root=(1-[0-9a-f]{8}-[0-9a-f]{24})(?:;|$)")


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _reap_log_group(ctx, group):
    """delete_function leaves /aws/lambda/<fn>, and a buffered stream can flush after the delete
    and RECREATE it: re-delete until the group stays absent for a 30 s quiet window (bounded)."""
    logs = ctx.client("logs")
    quiet = 0
    for _ in range(16):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 6:
                return
        time.sleep(5)


def _make_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-rt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC))
    return arn


def _wait_ready(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} "
                                 f"{last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _create_function(ctx, lam, role_arn, name, **kwargs):
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(FunctionName=name, Role=role_arn,
                                Tags={"sim2real": CHECK}, **kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    return _wait_ready(lam, name)


def _invoke(lam, fn, qualifier=None):
    kw = {"Qualifier": qualifier} if qualifier else {}
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=b"{}", **kw)
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"{fn}:{qualifier} FunctionError={resp.get('FunctionError')!r}: {raw[:400]!r}")
    return json.loads(raw)


def _assert_identity(body, *, fn, version, memory, group, region, label):
    env = body["env"]
    assert env["AWS_LAMBDA_FUNCTION_NAME"] == fn, (
        f"{label}: AWS_LAMBDA_FUNCTION_NAME={env['AWS_LAMBDA_FUNCTION_NAME']!r}, expected {fn!r}")
    assert env["AWS_LAMBDA_FUNCTION_VERSION"] == version, (
        f"{label}: AWS_LAMBDA_FUNCTION_VERSION={env['AWS_LAMBDA_FUNCTION_VERSION']!r}, "
        f"expected {version!r}")
    assert env["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"] == str(memory), (
        f"{label}: AWS_LAMBDA_FUNCTION_MEMORY_SIZE={env['AWS_LAMBDA_FUNCTION_MEMORY_SIZE']!r}, "
        f"expected {str(memory)!r}")
    assert env["AWS_LAMBDA_LOG_GROUP_NAME"] == group, (
        f"{label}: AWS_LAMBDA_LOG_GROUP_NAME={env['AWS_LAMBDA_LOG_GROUP_NAME']!r}, "
        f"expected {group!r}")
    assert body["log_group"] == group, (
        f"{label}: context.log_group_name={body['log_group']!r} disagrees with {group!r}")
    assert env["AWS_LAMBDA_LOG_STREAM_NAME"] == body["log_stream"], (
        f"{label}: AWS_LAMBDA_LOG_STREAM_NAME={env['AWS_LAMBDA_LOG_STREAM_NAME']!r} but "
        f"context.log_stream_name={body['log_stream']!r}")
    assert f"[{version}]" in body["log_stream"], (
        f"{label}: log stream {body['log_stream']!r} does not carry the served version "
        f"[{version}]")
    assert env["AWS_REGION"] == region, (
        f"{label}: AWS_REGION={env['AWS_REGION']!r}, expected {region!r}")
    assert env["AWS_LAMBDA_INITIALIZATION_TYPE"] == "on-demand", (
        f"{label}: AWS_LAMBDA_INITIALIZATION_TYPE={env['AWS_LAMBDA_INITIALIZATION_TYPE']!r}")
    assert env["_HANDLER"] == "index.handler", f"{label}: _HANDLER={env['_HANDLER']!r}"
    trace = env["_X_AMZN_TRACE_ID"] or ""
    m = _TRACE_RE.search(trace)
    assert m, f"{label}: _X_AMZN_TRACE_ID={trace!r} carries no Root=1-<8hex>-<24hex>"
    return m.group(1)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The guest's reserved environment variables track the served version, memory, log group and
    region, with a per-invocation trace root; a published version keeps its publish-time values.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    region = ctx.region
    role_arn = _make_role(ctx)
    fn = ctx.unique_name("sim2real-behav-rt-env-")
    default_group = f"/aws/lambda/{fn}"
    custom_group = f"/aws/sim2real/{fn}"
    ctx.on_cleanup(lambda: _reap_log_group(ctx, custom_group))
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _PROBE})}, MemorySize=256, Timeout=30,
    )

    # ---- $LATEST: identity, and a fresh trace root per invocation ----
    a = _invoke(lam, fn)
    b = _invoke(lam, fn)
    root_a = _assert_identity(a, fn=fn, version="$LATEST", memory=256, group=default_group,
                              region=region, label="$LATEST#1")
    root_b = _assert_identity(b, fn=fn, version="$LATEST", memory=256, group=default_group,
                              region=region, label="$LATEST#2")
    assert root_a != root_b, (
        f"two invocations reported the same _X_AMZN_TRACE_ID Root {root_a!r}; the trace id must be "
        f"per-invocation, not per-environment")
    assert a["request_id"] != b["request_id"], f"request ids collided: {a['request_id']!r}"

    # ---- a published version reports ITS version number ----
    ver = lam.publish_version(FunctionName=fn)["Version"]
    assert ver.isdigit(), f"PublishVersion returned non-numeric version {ver!r}"
    v = _invoke(lam, fn, qualifier=ver)
    _assert_identity(v, fn=fn, version=ver, memory=256, group=default_group, region=region,
                     label=f"version {ver}")

    # ---- change memory and the log destination on $LATEST only ----
    lam.update_function_configuration(
        FunctionName=fn, MemorySize=512,
        LoggingConfig={"LogFormat": "Text", "LogGroup": custom_group},
    )
    cfg = _wait_ready(lam, fn)
    assert cfg["LoggingConfig"]["LogGroup"] == custom_group, (
        f"LoggingConfig did not land: {cfg.get('LoggingConfig')!r}")
    after = _invoke(lam, fn)
    _assert_identity(after, fn=fn, version="$LATEST", memory=512, group=custom_group,
                     region=region, label="$LATEST after update")

    # ---- the published version is frozen at its publish-time configuration ----
    v2 = _invoke(lam, fn, qualifier=ver)
    _assert_identity(v2, fn=fn, version=ver, memory=256, group=default_group, region=region,
                     label=f"version {ver} after $LATEST update")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
