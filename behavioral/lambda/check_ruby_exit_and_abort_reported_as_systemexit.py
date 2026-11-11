"""ruby-exit-and-abort-reported-as-systemexit."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'ruby-exit-and-abort-reported-as-systemexit'
GROUP = 'rejection'
SERVICES = ['lambda']

_RUNTIME = "ruby3.3"

_HANDLER = (
    'def handler(event:, context:)\n'
    '  if event["op"] == "exit"\n'
    '    exit(2)\n'
    '  elsif event["op"] == "abort"\n'
    '    abort("sim2real abort message")\n'
    '  end\n'
    '  {"ok" => true}\n'
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Kernel#abort(msg) escapes the handler as Function<SystemExit> with msg as errorMessage,
    unlike Kernel#exit, which always reports the fixed errorMessage "exit": both paths raise the
    same Ruby class but only abort's text is observer-controlled.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/ruby-exceptions.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "rbxa", _make_zip([("lambda_function.rb", _HANDLER, 0o100644)]),
                   runtime=_RUNTIME, handler="lambda_function.handler",
                   Architectures=["x86_64"])

    control_err, control_body = _invoke(lam, fn, {"op": "neither"})
    assert control_err is None, f"positive control: unexpected FunctionError {control_err!r}"
    assert control_body == {"ok": True}, f"positive control returned {control_body!r}"

    # exit(2) is only the contrast baseline for abort below: its own message is fixed "exit"
    # regardless of the status code passed.
    exit_err, exit_body = _invoke(lam, fn, {"op": "exit"})
    assert exit_err == "Unhandled", f"exit(2): FunctionError={exit_err!r}, payload {exit_body!r}"
    assert exit_body.get("errorType") == "Function<SystemExit>", (
        f"exit(2): expected errorType Function<SystemExit>, got {exit_body.get('errorType')!r}")
    assert exit_body.get("errorMessage") == "exit", (
        f"exit(2): a status code given to exit does not change SystemExit's own message; "
        f"expected errorMessage 'exit', got {exit_body.get('errorMessage')!r}")

    # The check's own claim: unlike exit, abort's message is observer-controlled.
    abort_err, abort_body = _invoke(lam, fn, {"op": "abort"})
    assert abort_err == "Unhandled", (
        f"abort(msg): FunctionError={abort_err!r}, payload {abort_body!r}")
    assert abort_body.get("errorType") == "Function<SystemExit>", (
        f"abort(msg): expected errorType Function<SystemExit>, got {abort_body.get('errorType')!r}")
    assert abort_body.get("errorMessage") == "sim2real abort message", (
        f"abort(msg): expected errorMessage to be the abort message, got "
        f"{abort_body.get('errorMessage')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
