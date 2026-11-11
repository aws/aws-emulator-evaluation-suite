"""snapstart-python-version-restores-with-before-snapshot-state-and-a-restore-report."""
from __future__ import annotations

import base64
import io
import json
import re
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapstart-python-version-restores-with-before-snapshot-state-and-a-restore-report"
GROUP = "data-plane"
SERVICES = ["lambda"]

_HANDLER = """\
import os
from snapshot_restore_py import register_after_restore, register_before_snapshot

STATE = {"before": 0, "after": 0}


@register_before_snapshot
def _before():
    STATE["before"] += 1


@register_after_restore
def _after():
    STATE["after"] += 1


def handler(event, context):
    return {"before": STATE["before"], "after": STATE["after"],
            "version": context.function_version}
"""

_REPORT = re.compile(r"^REPORT RequestId: (?P<rid>\S+)\t(?P<rest>.*)$", re.M)
_FIELD = re.compile(r"(?P<k>[A-Za-z][A-Za-z ]*): (?P<v>[0-9.]+) (?:ms|MB)")


def _report_fields(log: str, request_id: str) -> dict:
    """The named numeric fields of this request's REPORT line in the log tail."""
    for m in _REPORT.finditer(log):
        if m["rid"] == request_id:
            return {f["k"].strip(): float(f["v"]) for f in _FIELD.finditer(m["rest"])}
    raise AssertionError(f"no REPORT line for {request_id} in the log tail: {log[-600:]!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SnapStart python3.12 version (OptimizationStatus On) runs restored with before/after hooks
    each run once and a REPORT with Restore Duration and Billed Restore Duration but no Init
    Duration; $LATEST (Off) runs no hook and reports Init Duration and no Restore Duration.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/snapstart-runtime-hooks-python.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/snapstart-monitoring.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-snappy-")
    _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=512, Timeout=15,
              Code={"ZipFile": _zip({"index.py": (_HANDLER, 0o644)})},
              SnapStart={"ApplyOn": "PublishedVersions"})
    version = lam.publish_version(FunctionName=fn)["Version"]
    vconf = _poll(lambda: lam.get_function_configuration(FunctionName=fn, Qualifier=version),
                  lambda c: c.get("State") in ("Active", "Failed"), timeout_s=600,
                  interval_s=5, what=f"SnapStart version {version} leaves Pending")
    assert vconf["State"] == "Active", f"version {version}: {vconf['State']!r} {vconf.get('StateReason')!r}"
    assert vconf["SnapStart"] == {"ApplyOn": "PublishedVersions", "OptimizationStatus": "On"}, (
        f"version {version} SnapStart {vconf['SnapStart']!r}")
    latest = lam.get_function_configuration(FunctionName=fn)
    assert latest["SnapStart"] == {"ApplyOn": "PublishedVersions", "OptimizationStatus": "Off"}, (
        f"$LATEST SnapStart {latest['SnapStart']!r}")

    r = _invoke(lam, fn, b"{}", qualifier=version)
    assert r["error"] is None, f"version invoke failed: {r['error']!r} {r['raw'][:400]!r}"
    body = json.loads(r["raw"])
    assert body == {"before": 1, "after": 1, "version": version}, (
        f"restored environment reports {body!r}")
    fields = _report_fields(r["log"], r["request_id"])
    assert "Restore Duration" in fields and "Billed Restore Duration" in fields, (
        f"restored REPORT fields {sorted(fields)!r}")
    assert "Init Duration" not in fields, f"restored REPORT has Init Duration: {sorted(fields)!r}"

    cold = _invoke(lam, fn, b"{}")
    assert cold["error"] is None, f"$LATEST invoke failed: {cold['error']!r}"
    assert json.loads(cold["raw"]) == {"before": 0, "after": 0, "version": "$LATEST"}, (
        f"$LATEST ran a SnapStart hook: {cold['raw']!r}")
    cfields = _report_fields(cold["log"], cold["request_id"])
    assert "Init Duration" in cfields and "Restore Duration" not in cfields, (
        f"$LATEST cold REPORT fields {sorted(cfields)!r}")


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
