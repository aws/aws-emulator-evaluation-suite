"""nodejs22-execution-role-credentials-in-environment."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs22-execution-role-credentials-in-environment"
GROUP = "permission-chain"
SERVICES = ["iam", "lambda", "sts"]

# The handler reports only whether each credential variable is set, never a value.
_HANDLER = r"""
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const KEYS = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'];
exports.handler = async () => {
  const e = process.env;
  const present = {};
  for (const k of KEYS) present[k] = typeof e[k] === 'string' && e[k].length > 0;
  const out = { present };
  try {
    const client = new STSClient({});
    const id = await client.send(new GetCallerIdentityCommand({}));
    out.arn = id.Arn;
    out.account = id.Account;
    const creds = await client.config.credentials();
    out.sdkUsesEnvKey = present.AWS_ACCESS_KEY_ID && creds.accessKeyId === e.AWS_ACCESS_KEY_ID;
    out.sdkUsesEnvToken = present.AWS_SESSION_TOKEN && creds.sessionToken === e.AWS_SESSION_TOKEN;
  } catch (err) {
    out.stsError = { name: err.name, message: err.message };
  }
  return out;
};
"""

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """nodejs22.x (the python3.12 identity check does not cover Node): process.env sets the three
    credential variables (checked as booleans only), SDK v3's default chain signs with them, and
    GetCallerIdentity from the handler is the execution role's session named for the function.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    fn = _deploy(ctx, lam, role["arn"], {"index.js": _HANDLER})
    part = _partition(ctx)

    got = _ok(lam, fn, {})
    present = got.get("present") or {}
    assert present == {k: True for k in _KEYS}, (
        f"credential variables set in the nodejs22.x environment: {present!r}, expected all three")
    assert got.get("stsError") is None, (
        f"SDK v3 GetCallerIdentity in the handler failed: {got.get('stsError')!r}")
    assert got.get("sdkUsesEnvKey") is True and got.get("sdkUsesEnvToken") is True, (
        f"SDK v3 default credentials are not the environment's: key {got.get('sdkUsesEnvKey')!r}, "
        f"token {got.get('sdkUsesEnvToken')!r}")
    assert got.get("account") == ctx.account, "GetCallerIdentity in the handler names another account"
    arn = str(got.get("arn"))
    want = f"arn:{part}:sts::{ctx.account}:assumed-role/{role['name']}/{fn}"
    assert arn == want, (
        "GetCallerIdentity in the handler is not the execution role's session named for the function "
        f"(resource type {arn.split(':')[5].split('/')[0] if arn.count(':') >= 5 else None!r}, "
        f"{arn.count('/')} '/' separators)")


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


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], "the caller's ARN does not parse"
    return parts[1]


def _exec_role(ctx) -> dict:
    """This check's own execution role. It carries no policy, so the function cannot write a log
    group: nothing outlives the function's delete."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str, files: dict) -> str:
    """Create a nodejs22.x function from inline ``files``, wait for Active, register its delete."""
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = dict(
        FunctionName=name, Runtime="nodejs22.x", Handler="index.handler", Role=role,
        Code={"ZipFile": _zip(files)}, MemorySize=256, Timeout=20,
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s; last {cfg['State']!r}"
        time.sleep(1)


def _ok(lam, name: str, payload) -> dict:
    """RequestResponse invoke returning the decoded result; fails on a FunctionError."""
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}, expected 200"
    raw = resp["Payload"].read()
    assert resp.get("FunctionError") is None, (
        f"Invoke {name}: FunctionError={resp.get('FunctionError')!r}, payload {raw[:600]!r}")
    body = json.loads(raw)
    assert isinstance(body, dict), f"Invoke {name}: result {body!r} is not an object"
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
