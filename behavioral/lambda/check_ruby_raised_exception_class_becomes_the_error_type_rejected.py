"""ruby-raised-exception-class-becomes-the-error-type-rejected."""

from __future__ import annotations

import base64
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ruby-raised-exception-class-becomes-the-error-type-rejected"
GROUP = 'rejection'
SERVICES = ['lambda']

RUBY = r'''require 'json'

module Billing
  class CardDeclined < StandardError; end
  module Ledger
    class Imbalanced < StandardError
      def initialize(msg = "ledger does not balance")
        super
      end
    end
  end
end

def handler(event:, context:)
  case event["raise"]
  when "custom" then raise Billing::CardDeclined, "card #{event['nonce']} declined"
  when "nested" then raise Billing::Ledger::Imbalanced
  when "zero" then 1 / 0
  when "string" then raise "plain #{event['nonce']}"
  when "exception" then raise Exception, "base class"
  when "multiline" then raise ArgumentError, "line one\nline two"
  else {"ok" => event["nonce"]}
  end
end
'''



def _raise_line(arm):
    """The 1-based line of RUBY holding the ``when "<arm>"`` branch that raises."""
    lines = [i for i, ln in enumerate(RUBY.splitlines(), start=1) if f'when "{arm}"' in ln]
    assert len(lines) == 1, f"the Ruby source has {len(lines)} branches for {arm!r}"
    return lines[0]

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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An exception escaping a Ruby handler fails the invoke with errorType
    Function<FullyQualifiedClass>, errorMessage the exception message, and a stackTrace ending at
    the raising line of /var/task/lambda_function.rb; the document has exactly those three keys.
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    nonce = uuid.uuid4().hex[:12]
    fn = _function(ctx, lam, role, "rbraise", _make_zip([("lambda_function.rb", RUBY, 0o100644)]),
                   runtime="ruby3.4", handler="lambda_function.handler")

    control = _invoke(lam, fn, {"nonce": nonce})
    assert _ok(fn, control) == {"ok": nonce}, f"the control invoke returned {control['raw']!r}"

    expected = {
        "custom": ("Function<Billing::CardDeclined>", f"card {nonce} declined"),
        "nested": ("Function<Billing::Ledger::Imbalanced>", "ledger does not balance"),
        "zero": ("Function<ZeroDivisionError>", "divided by 0"),
        "string": ("Function<RuntimeError>", f"plain {nonce}"),
        "exception": ("Function<Exception>", "base class"),
        "multiline": ("Function<ArgumentError>", "line one\nline two"),
    }
    for arm, (error_type, message) in expected.items():
        doc = _failed(fn, _invoke(lam, fn, {"raise": arm, "nonce": nonce}))
        assert doc["errorType"] == error_type, (
            f"raising {arm!r} produced errorType {doc['errorType']!r}, expected {error_type!r}")
        assert doc["errorMessage"] == message, (
            f"raising {arm!r} produced errorMessage {doc['errorMessage']!r}, expected {message!r}")
        frames = [f for f in doc["stackTrace"] if f.startswith("/var/task/lambda_function.rb:")]
        assert frames and frames[-1].startswith(f"/var/task/lambda_function.rb:{_raise_line(arm)}:"), (
            f"raising {arm!r}: the stack trace's handler frames are {frames!r}; the handler frame "
            f"must name line {_raise_line(arm)} of the function's own source")
        assert set(doc) == {"errorType", "errorMessage", "stackTrace"}, (
            f"raising {arm!r}: the error document has keys {sorted(doc)!r}")

    after = _invoke(lam, fn, {"nonce": nonce})
    assert _ok(fn, after) == {"ok": nonce}, f"the handler did not recover: {after['raw']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
