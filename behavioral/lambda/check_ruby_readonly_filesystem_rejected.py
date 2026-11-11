"""ruby-readonly-filesystem-rejected."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'ruby-readonly-filesystem-rejected'
GROUP = 'packaging'
SERVICES = ['lambda']

_RUNTIME = "ruby4.0"

_HANDLER = (
    'def handler(event:, context:)\n'
    '  if event["op"] == "tmp"\n'
    '    File.write("/tmp/sim2real-rofs.txt", event["token"])\n'
    '    return {"tmp" => File.read("/tmp/sim2real-rofs.txt")}\n'
    '  end\n'
    '  # Deliberately unguarded: the raised SystemCallError leaves the handler as the error.\n'
    '  File.write(event["path"], event["token"])\n'
    '  {"wrote" => event["path"]}\n'
    'end\n'
)

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(ctx, name, *, reads=3, interval_s=4.0, budget_s=60.0):
    logs = ctx.client("logs")

    def _reap():
        deadline = time.monotonic() + budget_s
        absent = 0
        while absent < reads:
            present = any(g["logGroupName"] == name
                         for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
            if present:
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
                    raise AssertionError(f"log group {name!r} still present after {budget_s}s")
                time.sleep(interval_s)

    ctx.on_cleanup(_reap)


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data.encode() if isinstance(data, str) else data)
    return buf.getvalue()


def _execution_role(ctx):
    iam = ctx.client("iam")
    policy_arn = _BASIC_EXEC.format(partition=_partition(ctx))
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
    name = ctx.unique_name(f"sim2real-l3-{label}-")
    _reap_log_group(ctx, f"/aws/lambda/{name}")
    kwargs = dict(FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
                  Code={"ZipFile": zipbytes}, MemorySize=256, Timeout=15,
                  Tags={"sim2real": CHECK})
    kwargs.update(extra)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValueException"
                    or err["Message"] != _ROLE_NOT_READY or time.monotonic() > deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_settled(lam, name)
    return name


def _wait_settled(lam, name, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        assert time.monotonic() < deadline, (
            f"{name} did not settle within {timeout_s}s: State={cfg['State']!r} "
            f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}")
        time.sleep(1)


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, (
        f"{name}: a synchronous invoke always returns StatusCode 200, even on a handler "
        f"failure; got {resp['StatusCode']!r}")
    return resp.get("FunctionError"), json.loads(resp["Payload"].read())


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """/var/task and /var/runtime are read-only for a Ruby function: File.write into either raises
    Function<Errno::EROFS> out of the handler with Ruby's own "Read-only file system @ rb_sysopen
    - <path>" message, while /tmp in the same sandbox accepts a write and reads it back.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    token = uuid.uuid4().hex
    fn = _function(ctx, lam, role, "rbro", _make_zip([("lambda_function.rb", _HANDLER, 0o100644)]),
                   runtime=_RUNTIME, handler="lambda_function.handler",
                   Architectures=["arm64"])

    tmp_err, tmp_body = _invoke(lam, fn, {"op": "tmp", "token": token})
    assert tmp_err is None, f"/tmp write failed: FunctionError={tmp_err!r}, payload {tmp_body!r}"
    assert tmp_body == {"tmp": token}, f"/tmp must be writable (positive control); got {tmp_body!r}"

    for path in ("/var/task/sim2real-new.txt", "/var/runtime/sim2real-new.txt"):
        err, body = _invoke(lam, fn, {"op": "write", "path": path, "token": token})
        assert err == "Unhandled", (
            f"File.write({path!r}) must raise out of the handler; FunctionError={err!r}, "
            f"payload {body!r}")
        assert body.get("errorType") == "Function<Errno::EROFS>", (
            f"expected Function<Errno::EROFS> for a write to {path}; payload {body!r}")
        assert body.get("errorMessage") == f"Read-only file system @ rb_sysopen - {path}", (
            f"the write to {path} must fail EROFS with Ruby's own message; got "
            f"{body.get('errorMessage')!r}")

    again_err, again_body = _invoke(lam, fn, {"op": "tmp", "token": token})
    assert again_err is None, f"/tmp re-check failed: FunctionError={again_err!r}"
    assert again_body == {"tmp": token}, (
        f"the function must still run its deployed code after the rejected writes; got "
        f"{again_body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
