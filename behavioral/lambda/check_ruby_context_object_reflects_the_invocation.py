"""ruby-context-object-reflects-the-invocation."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ruby-context-object-reflects-the-invocation"
GROUP = 'data-plane'
SERVICES = ['lambda']

RUBY = r'''require 'json'

def handler(event:, context:)
  first = context.get_remaining_time_in_millis
  sleep 0.3
  {
    "function_name" => context.function_name,
    "function_version" => context.function_version,
    "invoked_function_arn" => context.invoked_function_arn,
    "memory_limit_in_mb" => context.memory_limit_in_mb,
    "aws_request_id" => context.aws_request_id,
    "log_group_name" => context.log_group_name,
    "log_stream_name" => context.log_stream_name,
    "deadline_ms" => context.deadline_ms,
    "remaining_first" => first,
    "remaining_later" => context.get_remaining_time_in_millis,
    "now_ms" => (Time.now.to_f * 1000).to_i,
    "client_context" => context.client_context,
    "client_context_class" => context.client_context.class.name,
    "identity_class" => context.identity.class.name,
  }
end
'''

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_groups(logs, names, *, reads=3, interval_s=4.0, budget_s=40.0):
    """Delete every group in ``names`` until ``reads`` consecutive rounds find all absent.

    A log stream an invocation buffered can flush after the function is deleted and recreate its
    group, so one delete is one round, not a teardown. Raises if a group is still coming back.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = [
            name for name in names
            if any(g["logGroupName"] == name
                   for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
        ]
        for name in present:
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        absent = 0 if present else absent + 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log groups {present!r} still present after {budget_s}s")
            time.sleep(interval_s)


_LOG_GROUPS: list = []


def _log_groups(ctx):
    """This run's /aws/lambda group names; one reap, registered before the first function, covers all."""
    for owner, names in _LOG_GROUPS:
        if owner is ctx:
            return names
    names: list = []
    _LOG_GROUPS.append((ctx, names))
    logs = ctx.client("logs")
    # Registered BEFORE any create, so LIFO runs it after every function has been deleted.
    ctx.on_cleanup(lambda: _reap_log_groups(logs, names))
    return names


def _make_zip(entries):
    """A deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _execution_role(ctx):
    """An execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
    """Create a function, register its teardown and log-group reap, and wait for State=Active."""
    name = ctx.unique_name(f"sim2real-l3-{label}-")
    _log_groups(ctx).append(f"/aws/lambda/{name}")
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
            # IAM propagation of the role created above exposes no condition to poll.
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


def _invoke(lam, name, payload, **extra):
    """Invoke synchronously with the log tail; ``payload`` is raw bytes or a JSON-able value."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    before_ms = time.time() * 1000.0
    resp = lam.invoke(FunctionName=name, Payload=body, LogType="Tail", **extra)
    after_ms = time.time() * 1000.0
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": resp["Payload"].read(),
        "content_type": resp["ResponseMetadata"]["HTTPHeaders"].get("content-type"),
        "request_id": resp["ResponseMetadata"]["RequestId"],
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
        "before_ms": before_ms,
        "after_ms": after_ms,
    }


def _ok(name, r):
    """The JSON body of a successful invoke; fails naming the error otherwise."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] is None, (
        f"{name}: FunctionError={r['function_error']!r}, payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


def _failed(name, r):
    """The JSON error document of an invoke that must report FunctionError=Unhandled."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] == "Unhandled", (
        f"{name}: FunctionError={r['function_error']!r} (expected 'Unhandled'), "
        f"payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Ruby context carries the Invoke's request id, function name, qualifier-following ARN and
    version, memory as a String, log group and stream, a deadline and falling remaining time within
    Timeout, and client_context as the caller's decoded Hash (nil when none was sent).

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "rbctx", _make_zip([("lambda_function.rb", RUBY, 0o100644)]),
                   runtime="ruby3.4", handler="lambda_function.handler")
    cfg = lam.get_function_configuration(FunctionName=fn)
    version = lam.publish_version(FunctionName=fn)["Version"]
    alias = "current"
    lam.create_alias(FunctionName=fn, Name=alias, FunctionVersion=version)
    ctx.on_cleanup(_teardown(lambda: lam.delete_alias(FunctionName=fn, Name=alias),
                             "ResourceNotFoundException"))

    nonce = uuid.uuid4().hex
    client_context = {"custom": {"nonce": nonce}, "client": {"app_title": "probe"}, "env": {"n": 1}}
    encoded = base64.b64encode(json.dumps(client_context).encode()).decode()

    r = _invoke(lam, fn, {"leg": "plain"}, ClientContext=encoded)
    c = _ok(fn, r)
    assert c["aws_request_id"] == r["request_id"], (
        f"context.aws_request_id is {c['aws_request_id']!r}, the caller's Invoke request id is "
        f"{r['request_id']!r}")
    assert c["function_name"] == fn, f"context.function_name is {c['function_name']!r}"
    assert c["function_version"] == "$LATEST", f"function_version is {c['function_version']!r}"
    assert c["invoked_function_arn"] == cfg["FunctionArn"], (
        f"an unqualified invoke reported invoked_function_arn {c['invoked_function_arn']!r}, "
        f"expected the function ARN GetFunctionConfiguration returns")
    # The Ruby runtime exposes the memory size as the String it reads from its environment.
    assert c["memory_limit_in_mb"] == str(cfg["MemorySize"]), (
        f"memory_limit_in_mb is {c['memory_limit_in_mb']!r}; the function has {cfg['MemorySize']!r} "
        f"MB and the Ruby runtime reports it as the string {str(cfg['MemorySize'])!r}")
    assert c["log_group_name"] == f"/aws/lambda/{fn}", f"log_group_name is {c['log_group_name']!r}"
    assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\[\$LATEST\][0-9a-f]{32}", c["log_stream_name"]), (
        f"log_stream_name {c['log_stream_name']!r} is not <date>/[$LATEST]<32 hex>")
    assert r["before_ms"] < c["deadline_ms"] <= r["after_ms"] + 15_000, (
        f"deadline_ms {c['deadline_ms']!r} is outside the caller's window "
        f"[{r['before_ms']:.0f}, {r['after_ms'] + 15_000:.0f}] for Timeout=15s")
    assert 0 < c["remaining_later"] < c["remaining_first"] <= 15_000, (
        f"get_remaining_time_in_millis went {c['remaining_first']!r} -> {c['remaining_later']!r} "
        f"across a 0.3 s sleep; it must be positive, bounded by the 15 s timeout, and fall")
    assert abs((c["deadline_ms"] - c["now_ms"]) - c["remaining_later"]) <= 1_000, (
        f"remaining time {c['remaining_later']!r} disagrees with deadline_ms - now = "
        f"{c['deadline_ms'] - c['now_ms']!r}")
    assert c["client_context_class"] == "Hash" and c["client_context"] == client_context, (
        f"context.client_context is a {c['client_context_class']} {c['client_context']!r}; it must "
        f"be the caller's ClientContext decoded into a Hash: {client_context!r}")
    assert c["identity_class"] == "NilClass", (
        f"context.identity is a {c['identity_class']} for an invoke with no Cognito identity")

    r = _invoke(lam, fn, {"leg": "alias"}, Qualifier=alias)
    a = _ok(fn, r)
    assert a["aws_request_id"] == r["request_id"], f"alias leg request id {a['aws_request_id']!r}"
    assert a["invoked_function_arn"] == f"{cfg['FunctionArn']}:{alias}", (
        f"invoked through alias {alias!r} the context reported {a['invoked_function_arn']!r}")
    assert a["function_version"] == version, (
        f"the alias resolves to version {version!r} but function_version is {a['function_version']!r}")
    # effect-absent: no ClientContext on this invoke, none in the context
    assert a["client_context_class"] == "NilClass" and a["client_context"] is None, (
        f"an invoke with no ClientContext still saw client_context={a['client_context']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
