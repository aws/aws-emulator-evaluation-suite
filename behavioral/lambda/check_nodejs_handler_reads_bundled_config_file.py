"""nodejs-handler-reads-bundled-config-file."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-handler-reads-bundled-config-file"
GROUP = "nodejs-handler"
SERVICES = ['lambda']


_RUNTIME = "nodejs22.x"
_SETTINGS = '{"feature": "on", "limit": 7, "name": "caf\u00e9"}\n'
_FILES = {
    "config/settings.json": _SETTINGS,
    "index.js": """\
const fs = require("fs");
const path = require("path");

exports.handler = async () => {
  const viaRoot = path.join(process.env.LAMBDA_TASK_ROOT, "config/settings.json");
  const viaDir = path.join(__dirname, "config/settings.json");
  const a = fs.readFileSync(viaRoot, "utf8");
  const b = fs.readFileSync(viaDir, "utf8");
  return { taskRoot: process.env.LAMBDA_TASK_ROOT, dirname: __dirname, viaRoot: a, viaDir: b,
           parsed: JSON.parse(a) };
};
""",
}



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A file bundled in a Node.js function's package reads back byte for byte from under
    LAMBDA_TASK_ROOT and from the handler's own __dirname, which are the same directory.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _FILES)
    out = _invoke_ok(ctx, fn["name"])
    assert out["taskRoot"] == "/var/task", f"LAMBDA_TASK_ROOT was {out['taskRoot']!r}"
    assert out["dirname"] == "/var/task", f"the handler's __dirname was {out['dirname']!r}"
    assert out["viaRoot"] == _SETTINGS, f"readFileSync under LAMBDA_TASK_ROOT returned {out['viaRoot']!r}"
    assert out["viaDir"] == _SETTINGS, f"readFileSync under __dirname returned {out['viaDir']!r}"
    assert out["parsed"] == json.loads(_SETTINGS), f"the bundled JSON parsed as {out['parsed']!r}"



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


def _zip(files: dict) -> bytes:
    """A deployment package holding ``files`` (archive path -> source text)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in sorted(files.items()):
            zf.writestr(path, textwrap.dedent(text))
    return buf.getvalue()


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


def _function(ctx, role_arn, code, *, timeout=60) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must not report a FunctionError."""
    err, out = _invoke(ctx, fn, event)
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
