"""nodejs22-environment-keys-without-session-token-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs22-environment-keys-without-session-token-rejected"
GROUP = "permission-chain"
SERVICES = ["iam", "lambda", "sts"]

# The handler reports only whether each credential variable is set, never a value.
_HANDLER = r"""
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const KEYS = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'];
const call = async (credentials) => {
  try {
    const id = await new STSClient({ credentials }).send(new GetCallerIdentityCommand({}));
    return { ok: true, account: id.Account };
  } catch (err) {
    return { ok: false, name: err.name, message: err.message,
             status: err.$metadata ? err.$metadata.httpStatusCode : null };
  }
};
exports.handler = async () => {
  const e = process.env;
  const present = {};
  for (const k of KEYS) present[k] = typeof e[k] === 'string' && e[k].length > 0;
  const out = { present };
  if (!KEYS.every((k) => present[k])) return out;
  out.withToken = await call({ accessKeyId: e.AWS_ACCESS_KEY_ID,
    secretAccessKey: e.AWS_SECRET_ACCESS_KEY, sessionToken: e.AWS_SESSION_TOKEN });
  out.withoutToken = await call({ accessKeyId: e.AWS_ACCESS_KEY_ID,
    secretAccessKey: e.AWS_SECRET_ACCESS_KEY });
  return out;
};
"""

_INVALID_TOKEN = "The security token included in the request is invalid."

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A nodejs22.x function's environment keys are session credentials: SDK v3 signing with key,
    secret and token reaches STS, and the same key and secret without the token are refused 403
    InvalidClientTokenId with STS's exact message.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    fn = _deploy(ctx, lam, role["arn"], {"index.js": _HANDLER})

    got = _ok(lam, fn, {})
    present = got.get("present") or {}
    assert present == {k: True for k in _KEYS}, (
        f"credential variables set in the nodejs22.x environment: {present!r}, expected all three")
    good = got.get("withToken") or {}
    assert good.get("ok") is True and good.get("account") == ctx.account, (
        f"control: GetCallerIdentity with the environment's key, secret and token failed: "
        f"{good.get('name')!r} {good.get('message')!r}")
    bad = got.get("withoutToken") or {}
    assert bad.get("ok") is False, (
        "GetCallerIdentity signed with the environment's key and secret but no session token was "
        "accepted; temporary keys require their token")
    assert bad.get("status") == 403, f"the token-less call answered HTTP {bad.get('status')!r}, expected 403"
    assert bad.get("name") == "InvalidClientTokenId", (
        f"the token-less call answered {bad.get('name')!r}, expected 'InvalidClientTokenId'")
    assert bad.get("message") == _INVALID_TOKEN, (
        f"the token-less call answered message {bad.get('message')!r}, expected {_INVALID_TOKEN!r}")


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
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


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
