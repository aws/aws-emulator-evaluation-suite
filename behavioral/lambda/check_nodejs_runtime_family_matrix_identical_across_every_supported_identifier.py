"""nodejs-runtime-family-matrix-identical-across-every-supported-identifier."""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'nodejs-runtime-family-matrix-identical-across-every-supported-identifier'
GROUP = 'nodejs-runtime-family'
SERVICES = ['lambda']


_HANDLER = r"""
const crypto = require('crypto');
exports.handler = async (event) => {
  const canonical = JSON.stringify(event, Object.keys(event).sort());
  return {
    nodeMajor: process.version.split('.')[0].replace('v', ''),
    arch: process.arch,
    execEnv: process.env.AWS_EXECUTION_ENV || null,
    sha256: crypto.createHash('sha256').update(canonical).digest('hex'),
  };
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
    """The caller's own partition, read off its ARN rather than a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"GetCallerIdentity Arn {arn!r}"
    return parts[1]


def _exec_role(ctx):
    """This run's own Lambda execution role, created once."""
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
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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


def _deploy(ctx, lam, role: str, runtime: str, arch: str) -> str:
    """Create a function from the shared handler under one (Runtime, Architecture), wait Active."""
    name = ctx.unique_name("sim2real-behav-fn-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda n=name: _reap_log_group(logs, f"/aws/lambda/{n}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime=runtime, Handler="index.handler", Role=role,
                Code={"ZipFile": _zip({"index.js": _HANDLER})}, MemorySize=128, Timeout=10,
                Architectures=[arch], Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    assert resp["Runtime"] == runtime, f"CreateFunction echoed Runtime={resp['Runtime']!r}, expected {runtime!r}"
    assert resp["Architectures"] == [arch], f"CreateFunction echoed Architectures={resp['Architectures']!r}"
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n), "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} ({runtime}/{arch}) entered Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} ({runtime}/{arch}) not Active within 90s"
        time.sleep(1)


def _invoke(lam, name: str, payload) -> dict:
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}"
    assert not resp.get("FunctionError"), (
        f"Invoke {name}: FunctionError={resp.get('FunctionError')!r}, payload {resp['Payload'].read()!r}"
    )
    return json.loads(resp["Payload"].read())


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same unchanged Node.js handler, run under every supported nodejs identifier and
    rotated across both architectures, reports process.version/process.arch/AWS_EXECUTION_ENV
    matching its own Runtime, and hashes an identical event to the independently computed digest.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    payload = {"zeta": ctx.unique_name("z-"), "alpha": "first-key", "mid": 7}
    want = hashlib.sha256(
        json.dumps({k: payload[k] for k in sorted(payload)}, separators=(",", ":")).encode()
    ).hexdigest()

    matrix = (
        ("nodejs22.x", "22", "x86_64"),
        ("nodejs24.x", "24", "arm64"),
    )
    for runtime, major, arch in matrix:
        fn = _deploy(ctx, lam, role, runtime, arch)
        out = _invoke(lam, fn, payload)
        assert out.get("nodeMajor") == major, (
            f"{runtime}: process.version major was {out.get('nodeMajor')!r}, expected {major!r}"
        )
        assert out.get("arch") == ("x64" if arch == "x86_64" else "arm64"), (
            f"{runtime}/{arch}: process.arch was {out.get('arch')!r}"
        )
        assert out.get("execEnv") == f"AWS_Lambda_{runtime}", (
            f"{runtime}/{arch}: AWS_EXECUTION_ENV was {out.get('execEnv')!r}, expected "
            f"'AWS_Lambda_{runtime}'"
        )
        assert out.get("sha256") == want, (
            f"{runtime}/{arch}: handler hashed the event to {out.get('sha256')!r}, expected "
            f"the independently computed {want!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
