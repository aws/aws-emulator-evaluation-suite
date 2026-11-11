"""snapstart-on-a-runtime-without-snapstart-rejected."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapstart-on-a-runtime-without-snapstart-rejected"
GROUP = "validation"
SERVICES = ["lambda"]

_NODE = """\
exports.handler = async () => ({ ok: true });
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Setting SnapStart ApplyOn=PublishedVersions on a nodejs22.x function is refused with
    InvalidParameterValueException naming the runtime and SnapStart stays None; after switching the
    function to python3.12 the identical update succeeds and reads back.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-snapnode-")
    _function(ctx, FunctionName=fn, Runtime="nodejs22.x", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=256, Timeout=10,
              Code={"ZipFile": _zip({"index.js": (_NODE, 0o644)})})

    code, msg = _error(lambda: lam.update_function_configuration(
        FunctionName=fn, SnapStart={"ApplyOn": "PublishedVersions"}))
    assert (code, msg) == ("InvalidParameterValueException",
                           "nodejs22.x is not supported for SnapStart enabled functions."), (
        f"SnapStart on nodejs22.x refused with {code!r}: {msg!r}")
    conf = _wait_active(lam, fn)
    assert conf["SnapStart"]["ApplyOn"] == "None", f"after the refusal SnapStart is {conf['SnapStart']!r}"

    lam.update_function_code(FunctionName=fn, ZipFile=_zip(
        {"index.py": ("def handler(event, context):\n    return {'ok': True}\n", 0o644)}))
    _wait_active(lam, fn)
    lam.update_function_configuration(FunctionName=fn, Runtime="python3.12")
    _wait_active(lam, fn)
    lam.update_function_configuration(FunctionName=fn, SnapStart={"ApplyOn": "PublishedVersions"})
    conf = _wait_active(lam, fn)
    assert (conf["Runtime"], conf["SnapStart"]["ApplyOn"]) == ("python3.12", "PublishedVersions"), (
        f"on python3.12 the update reads back {conf['Runtime']!r} {conf['SnapStart']!r}")


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
