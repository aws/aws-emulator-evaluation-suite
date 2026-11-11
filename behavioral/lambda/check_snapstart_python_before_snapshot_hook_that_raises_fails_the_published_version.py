"""snapstart-python-before-snapshot-hook-that-raises-fails-the-published-version."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapstart-python-before-snapshot-hook-that-raises-fails-the-published-version"
GROUP = "data-plane"
SERVICES = ["lambda"]

SNAPSHOT_WAIT_S = 600

_HANDLER = """\
import os
from snapshot_restore_py import register_before_snapshot


@register_before_snapshot
def _before():
    if os.environ.get("HOOK_FAILS") == "yes":
        raise RuntimeError("probe-before-snapshot-failure")


def handler(event, context):
    return {"version": context.function_version}
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A SnapStart python3.12 version whose before-snapshot hook raises settles Failed (FunctionError,
    "An error occurred during function initialization.") and refuses invoke with
    ResourceConflictException, while $LATEST serves and a fixed republish is Active and serves.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/snapstart-runtime-hooks-python.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-snapfail-")
    _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=512, Timeout=15,
              Code={"ZipFile": _zip({"index.py": (_HANDLER, 0o644)})},
              SnapStart={"ApplyOn": "PublishedVersions"},
              Environment={"Variables": {"HOOK_FAILS": "yes"}})

    bad = lam.publish_version(FunctionName=fn)["Version"]
    conf = _settle(lam, fn, bad)
    assert (conf["State"], conf.get("StateReasonCode"), conf.get("StateReason")) == (
        "Failed", "FunctionError", "An error occurred during function initialization."), (
        f"version {bad} with a raising hook settled {conf['State']!r} "
        f"{conf.get('StateReasonCode')!r}: {conf.get('StateReason')!r}")
    code, msg = _error(lambda: lam.invoke(FunctionName=fn, Qualifier=bad, Payload=b"{}"))
    assert (code, msg) == ("ResourceConflictException", "The operation cannot be performed at "
                           "this time. The function is currently in the following state: Failed"), (
        f"invoking failed version {bad} answered {code!r}: {msg!r}")
    latest = _invoke(lam, fn, b"{}")
    assert latest["error"] is None and json.loads(latest["raw"]) == {"version": "$LATEST"}, (
        f"$LATEST stopped serving: {latest['error']!r} {latest['raw'][:300]!r}")

    lam.update_function_configuration(FunctionName=fn, Environment={
        "Variables": {"HOOK_FAILS": "no"}})
    _wait_active(lam, fn)
    good = lam.publish_version(FunctionName=fn)["Version"]
    gconf = _settle(lam, fn, good)
    assert gconf["State"] == "Active" and gconf["SnapStart"]["OptimizationStatus"] == "On", (
        f"version {good} settled {gconf['State']!r} {gconf.get('SnapStart')!r}")
    ok = _invoke(lam, fn, b"{}", qualifier=good)
    assert ok["error"] is None and json.loads(ok["raw"]) == {"version": good}, (
        f"version {good}: {ok['error']!r} {ok['raw'][:300]!r}")


def _settle(lam, fn, version) -> dict:
    return _poll(lambda: lam.get_function_configuration(FunctionName=fn, Qualifier=version),
                 lambda c: c.get("State") in ("Active", "Failed"), timeout_s=SNAPSHOT_WAIT_S,
                 interval_s=5, what=f"version {version} leaves Pending")


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn()`` raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, the call succeeded: {out!r}")


def _zip(files: dict) -> bytes:
    """A zip of ``{arcname: (text, mode)}``; the mode lands in the entry's Unix permission bits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, (text, mode) in files.items():
            info = zipfile.ZipInfo(arc, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, textwrap.dedent(text))
    return buf.getvalue()


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
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx, statements=None) -> str:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so no function
    of this check ever creates a log group that could outlive it (LogType=Tail needs none)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return arn


def _function(ctx, **kwargs) -> dict:
    """CreateFunction through the role-propagation window, its delete registered, then Active."""
    lam = ctx.client("lambda")
    kwargs.setdefault("Tags", {"sim2real": CHECK})

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
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_active(lam, name)
    return out


def _wait_active(lam, name, qualifier=None) -> dict:
    args = {"FunctionName": name}
    if qualifier:
        args["Qualifier"] = qualifier
    conf = _poll(lambda: lam.get_function_configuration(**args),
                 lambda c: c.get("State", "Active") in ("Active", "Failed")
                 and c.get("LastUpdateStatus", "Successful") != "InProgress",
                 timeout_s=300, interval_s=2, what=f"function {name} settles")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return conf


def _invoke(lam, name, payload: bytes, qualifier=None) -> dict:
    """One RequestResponse invoke with the log tail: status, error flag, raw payload, request id."""
    args = {"FunctionName": name, "InvocationType": "RequestResponse", "LogType": "Tail",
            "Payload": payload}
    if qualifier:
        args["Qualifier"] = qualifier
    resp = lam.invoke(**args)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(),
            "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
            "request_id": resp["ResponseMetadata"]["RequestId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
