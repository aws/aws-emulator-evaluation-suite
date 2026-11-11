"""function-runs-as-an-assumed-role-session-named-for-the-function."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-runs-as-an-assumed-role-session-named-for-the-function"
GROUP = "permission-chain"
SERVICES = ["iam", "lambda", "sts"]

_HANDLER = """\
import os
import boto3

def handler(event, context):
    ident = boto3.client("sts").get_caller_identity()
    creds = boto3.Session().get_credentials().get_frozen_credentials()
    env = os.environ
    return {
        "arn": ident["Arn"], "userId": ident["UserId"], "account": ident["Account"],
        "keyPrefix": env.get("AWS_ACCESS_KEY_ID", "")[:4],
        "hasSecret": bool(env.get("AWS_SECRET_ACCESS_KEY")),
        "hasToken": bool(env.get("AWS_SESSION_TOKEN")),
        "sdkUsesEnvKey": creds.access_key == env.get("AWS_ACCESS_KEY_ID"),
        "sdkUsesEnvToken": creds.token == env.get("AWS_SESSION_TOKEN"),
        "region": env.get("AWS_REGION"), "functionName": env.get("AWS_LAMBDA_FUNCTION_NAME"),
        "contextName": context.function_name,
    }
"""


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A function runs as an assumed-role session of its execution role: ASIA temporary keys and a
    session token in the environment feed the SDK, GetCallerIdentity returns
    assumed-role/<role>/<function> with UserId <RoleId>:<function>, and AWS_REGION is set.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _HANDLER)
    part = _partition(ctx)

    err, out = _invoke(ctx, fn["name"])
    assert err is None, f"the function failed: {err!r} {out!r}"
    assert out["arn"] == f"arn:{part}:sts::{ctx.account}:assumed-role/{role['name']}/{fn['name']}", (
        "GetCallerIdentity inside the function is not the execution role's session named for the "
        f"function (shape: {out['arn'].split(':')[2:3]!r}, account match "
        f"{out['account'] == ctx.account!r})")
    assert out["userId"] == f"{role['id']}:{fn['name']}", (
        "UserId inside the function is not '<RoleId>:<function name>'")
    assert out["account"] == ctx.account, "the function's identity is in another account"
    assert out["keyPrefix"] == "ASIA", (
        f"AWS_ACCESS_KEY_ID starts {out['keyPrefix']!r}, not the temporary-credential prefix ASIA")
    assert out["hasSecret"] and out["hasToken"], (
        f"secret present {out['hasSecret']!r}, session token present {out['hasToken']!r}")
    assert out["sdkUsesEnvKey"] and out["sdkUsesEnvToken"], (
        f"the SDK's default credentials are not the environment's: key {out['sdkUsesEnvKey']!r}, "
        f"token {out['sdkUsesEnvToken']!r}")
    assert out["region"] == ctx.region, f"AWS_REGION {out['region']!r} != {ctx.region!r}"
    assert out["functionName"] == out["contextName"] == fn["name"], (
        f"AWS_LAMBDA_FUNCTION_NAME {out['functionName']!r}, context {out['contextName']!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"unparseable caller ARN {arn!r}"
    return parts[1]


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, env=None, timeout=30) -> dict:
    """A python3.12 function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=_budget_s(ctx, 90.0), interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=_budget_s(ctx, 90.0), interval_s=1,
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
