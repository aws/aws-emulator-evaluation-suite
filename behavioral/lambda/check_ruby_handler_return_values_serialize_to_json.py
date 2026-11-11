"""ruby-handler-return-values-serialize-to-json."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ruby-handler-return-values-serialize-to-json"
GROUP = 'data-plane'
SERVICES = ['lambda']

RUBY = r'''require 'json'

class Opaque
  def initialize; @secret = 1; end
  def to_s = "opaque-object"
end

class CustomJson
  def to_json(*args) = {"via" => "to_json", "n" => 7}.to_json(*args)
end

def handler(event:, context:)
  case event["shape"]
  when "hash" then {sym_key: 1, "str_key" => [1, 2.5, nil, true, false], nested: {deep: "v"}}
  when "string" then "plain string"
  when "integer" then 42
  when "float" then 1.5
  when "nil" then nil
  when "array" then [1, "two", {three: 3}]
  when "true" then true
  when "symbol" then :a_symbol
  when "time" then Time.at(0).utc
  when "object" then Opaque.new
  when "to_json" then CustomJson.new
  when "unicode" then {"s" => "héllo \u{1F600}"}
  end
end
'''

# Each handler return value and the exact payload bytes real AWS produced for it.
EXPECTED = {
    "hash": b'{"sym_key":1,"str_key":[1,2.5,null,true,false],"nested":{"deep":"v"}}',
    "string": b'"plain string"',
    "integer": b"42",
    "float": b"1.5",
    "nil": b"null",
    "array": b'[1,"two",{"three":3}]',
    "true": b"true",
    "symbol": b'"a_symbol"',
    "time": b'"1970-01-01 00:00:00 UTC"',
    "object": b'"opaque-object"',
    "to_json": b'{"via":"to_json","n":7}',
    "unicode": '{"s":"héllo \U0001F600"}'.encode("utf-8"),
}

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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A ruby3.4 handler's return value is marshalled with Ruby's to_json rules into exact
    application/json payload bytes: symbols become strings, nil is null, a Time and JSON-less
    objects become their to_s, a class's own to_json is honoured, and UTF-8 is emitted unescaped.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/ruby-handler.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "rbret", _make_zip([("lambda_function.rb", RUBY, 0o100644)]),
                   runtime="ruby3.4", handler="lambda_function.handler")

    for shape, want in EXPECTED.items():
        r = _invoke(lam, fn, {"shape": shape})
        assert r["status"] == 200 and r["function_error"] is None, (
            f"returning the {shape!r} value failed: FunctionError={r['function_error']!r} "
            f"{r['raw'][:400]!r}")
        assert r["raw"] == want, (
            f"returning the {shape!r} value produced payload {r['raw']!r}; Ruby's JSON "
            f"marshalling gives {want!r}")
        assert r["content_type"] == "application/json", (
            f"the {shape!r} payload was typed {r['content_type']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
