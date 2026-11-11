"""nodejs-filesystem-outside-tmp-is-read-only-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'nodejs-filesystem-outside-tmp-is-read-only-rejected'
GROUP = 'nodejs-filesystem'
SERVICES = ['lambda']

_HANDLER = r"""
const fs = require('fs');
exports.handler = async (event) => {
  const out = {};
  for (const [label, path] of Object.entries(event.targets)) {
    try {
      fs.writeFileSync(path, 'x');
      out[label] = { ok: true };
    } catch (e) {
      out[label] = { ok: false, code: e.code, message: e.message };
    }
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
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _partition(ctx) -> str:
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"GetCallerIdentity Arn {arn!r}"
    return parts[1]


def _exec_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = _BASIC_EXEC.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

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
            assert time.monotonic() <= deadline, f"log group {name} still present after {budget_s}s"
            time.sleep(interval_s)


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str) -> str:
    name = ctx.unique_name("sim2real-behav-fn-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda n=name: _reap_log_group(logs, f"/aws/lambda/{n}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="nodejs24.x", Handler="index.handler", Role=role,
                Code={"ZipFile": _zip({"index.js": _HANDLER})}, MemorySize=128, Timeout=10,
                Architectures=["arm64"], Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n), "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s"
        time.sleep(1)


def _invoke(lam, fn, payload) -> dict:
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {fn}: StatusCode {resp['StatusCode']!r}"
    assert not resp.get("FunctionError"), (
        f"Invoke {fn}: FunctionError={resp.get('FunctionError')!r}, payload {resp['Payload'].read()!r}"
    )
    return json.loads(resp["Payload"].read())


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Node.js handler's fs.writeFileSync into /var/task, /var/runtime or / fails with code
    EROFS and the exact "EROFS: read-only file system, open '<path>'" message; the identical
    call into /tmp succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-context.html
    """
    lam = ctx.client("lambda")
    fn = _deploy(ctx, lam, _exec_role(ctx))

    targets = {
        "task": "/var/task/sim2real.txt",
        "runtime": "/var/runtime/sim2real.txt",
        "root": "/sim2real.txt",
        "tmp": "/tmp/sim2real.txt",
    }
    out = _invoke(lam, fn, {"targets": targets})

    assert out["tmp"] == {"ok": True}, f"positive control: write to /tmp failed: {out['tmp']!r}"
    for label, path in targets.items():
        if label == "tmp":
            continue
        got = out[label]
        assert got.get("ok") is False, f"write to {path!r} unexpectedly succeeded: {got!r}"
        assert got.get("code") == "EROFS", f"write to {path!r}: code {got.get('code')!r}, expected 'EROFS'"
        want = f"EROFS: read-only file system, open '{path}'"
        assert got.get("message") == want, (
            f"write to {path!r}: message {got.get('message')!r}, expected {want!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
