"""restore-next-without-snapstart-returns-404."""

from __future__ import annotations

import base64
import io
import json
import zipfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-next-without-snapstart-returns-404"
GROUP = "extensions_runtime"
SERVICES = ["lambda"]

RUNTIME = "python3.13"
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

HANDLER = """
import json
import os
import urllib.error
import urllib.request

RUNTIME_API = os.environ["AWS_LAMBDA_RUNTIME_API"]


def handler(event, context):
    url = "http://" + RUNTIME_API + "/2018-06-01/runtime/restore/next"
    req = urllib.request.Request(url, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return {"status": resp.status, "body": resp.read().decode()}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode()}
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
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
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-restore-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_ready(ctx, lam, name: str, qualifier: str | None = None, *, snapstart_on: bool = False,
                timeout_s: float = 180.0) -> dict:
    """Poll to State Active with no update in flight (and SnapStart On when asked); Failed raises."""
    args = {"FunctionName": name, **({"Qualifier": qualifier} if qualifier else {})}
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(**args)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"function failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        ready = cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful")
        if ready and (not snapstart_on
                      or (cfg.get("SnapStart") or {}).get("OptimizationStatus") == "On"):
            return cfg
        if time.monotonic() > deadline:
            raise TimeoutError(f"{name}:{qualifier} did not settle within {timeout_s:.0f}s: {cfg!r}")
        time.sleep(1.0)


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or (
                _ROLE_PROPAGATION not in msg
            ):
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"CreateFunction kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(ctx, lam, name)
    return name


def _probe(ctx, lam, fn: str, qualifier: str | None = None) -> dict:
    """Invoke the probing handler, retrying only the IAM role-propagation refusal Active can still
    race, and return what GET /runtime/restore/next answered inside the execution environment."""
    args = {"FunctionName": fn, **({"Qualifier": qualifier} if qualifier else {})}
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            resp = lam.invoke(InvocationType="RequestResponse", LogType="Tail", Payload=b"{}",
                              **args)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "AccessDeniedException" or _ROLE_PROPAGATION not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"Invoke kept failing on role propagation: {err!r}") from exc
            time.sleep(3)
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"the probing invoke of {fn}:{qualifier} must itself succeed: "
        f"StatusCode={resp.get('StatusCode')!r}, FunctionError={resp.get('FunctionError')!r}, "
        f"log={base64.b64decode(resp.get('LogResult', '')).decode('utf-8', 'replace')!r}"
    )
    return json.loads(resp["Payload"].read())


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GET /runtime/restore/next from a function with no SnapStart is refused with an empty-bodied
    404, while the same call from a SnapStart version, whose runtime already took its restore, is
    a 403.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))
    common = dict(Runtime=RUNTIME, Role=role_arn, Handler="index.handler",
                  Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=256, Timeout=15,
                  Tags={"sim2real": CHECK})

    fn = _create_function(ctx, lam, logs, FunctionName=ctx.unique_name("sim2real-behav-restore-"),
                          **common)
    conf = lam.get_function_configuration(FunctionName=fn)
    assert conf.get("SnapStart", {}).get("OptimizationStatus") == "Off", (
        f"the probed function must have SnapStart Off, got {conf.get('SnapStart')!r}"
    )
    observed = _probe(ctx, lam, fn)
    assert observed == {"status": 404, "body": ""}, (
        f"GET /runtime/restore/next on a function without SnapStart must be an empty-bodied 404, "
        f"got {observed!r}"
    )

    # Positive control: on a SnapStart version the route exists, and the runtime has already
    # called it during restore, so the handler's call is the documented 403, not a 404.
    snap_fn = _create_function(ctx, lam, logs,
                               FunctionName=ctx.unique_name("sim2real-behav-restore-snap-"),
                               SnapStart={"ApplyOn": "PublishedVersions"}, **common)
    version = lam.publish_version(FunctionName=snap_fn)["Version"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=snap_fn, Qualifier=version),
                             "ResourceNotFoundException"))
    _wait_ready(ctx, lam, snap_fn, version, snapstart_on=True, timeout_s=300.0)
    control = _probe(ctx, lam, snap_fn, version)
    assert control["status"] == 403, (
        f"GET /runtime/restore/next on a SnapStart version, after the runtime's own restore call, "
        f"must be a 403, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
