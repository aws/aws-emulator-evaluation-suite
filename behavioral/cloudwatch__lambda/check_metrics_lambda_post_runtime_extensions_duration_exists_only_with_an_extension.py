"""metrics-lambda-post-runtime-extensions-duration-exists-only-with-an-extension."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-post-runtime-extensions-duration-exists-only-with-an-extension"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_INVOKES = 3
_SLEEP_MS = 100
_EXT_HOLD_MS = 500
_METRIC_BUDGET_S = 240.0
_ABSENCE_HOLD_S = 30.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
import time


def handler(event, context):
    time.sleep(event.get("sleep_ms", 0) / 1000.0)
    if event.get("fail"):
        raise RuntimeError("sim2real deliberate failure")
    return {"ok": True}
'''

#: An external extension (stdlib only, built in-check) that registers for INVOKE and then holds
#: every invocation open for _EXT_HOLD_MS before asking for the next event. That hold outlives
#: the handler, so it is post-runtime extension time by construction.
_EXTENSION = '''#!/usr/bin/env python3
import json
import os
import time
import urllib.request

API = os.environ["AWS_LAMBDA_RUNTIME_API"]
NAME = os.path.basename(__file__)
req = urllib.request.Request(
    "http://%s/2020-01-01/extension/register" % API,
    data=json.dumps({"events": ["INVOKE"]}).encode(),
    headers={"Lambda-Extension-Name": NAME},
    method="POST",
)
with urllib.request.urlopen(req) as r:
    ident = r.headers.get("Lambda-Extension-Identifier")
while True:
    nxt = urllib.request.Request(
        "http://%s/2020-01-01/extension/event/next" % API,
        headers={"Lambda-Extension-Identifier": ident},
    )
    with urllib.request.urlopen(nxt) as r:
        json.loads(r.read())
    time.sleep(HOLD_MS / 1000.0)
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """A function with an extension that holds each invoke publishes PostRuntimeExtensionsDuration
    (Milliseconds, one sample per invoke, included in Duration), while the same function without the
    extension publishes Invocations but no PostRuntimeExtensionsDuration."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("extensions/sim2real-hold")
        info.external_attr = 0o755 << 16  # Lambda silently skips a non-executable extension
        zf.writestr(info, _EXTENSION.replace("HOLD_MS", str(_EXT_HOLD_MS)))
    layer = lam.publish_layer_version(
        LayerName=ctx.unique_name("sim2real-mlam-ext-")[:64],
        Content={"ZipFile": buf.getvalue()},
        CompatibleRuntimes=["python3.12"],
    )
    ctx.on_cleanup(
        lambda: lam.delete_layer_version(
            LayerName=layer["LayerArn"], VersionNumber=layer["Version"]
        )
    )

    with_ext = _function(ctx, lam, role_arn, "ext", Layers=[layer["LayerVersionArn"]])
    plain = _function(ctx, lam, role_arn, "plain")
    cfg = lam.get_function_configuration(FunctionName=with_ext)
    assert [x["Arn"] for x in cfg.get("Layers", [])] == [layer["LayerVersionArn"]], (
        f"{with_ext} does not carry the extension layer: {cfg.get('Layers')!r}"
    )

    for fn in (with_ext, plain):
        for _ in range(_INVOKES):
            r = lam.invoke(FunctionName=fn, Payload=json.dumps({"sleep_ms": _SLEEP_MS}).encode())
            body = json.loads(r["Payload"].read())
            assert r.get("FunctionError") is None and body == {"ok": True}, (
                f"invoke of {fn} returned {r.get('FunctionError')!r} {body!r}"
            )

    def _stats(fn: str, metric: str):
        dps = _series(cw, metric, [("FunctionName", fn)], start, ["SampleCount", "Minimum"])
        if not dps:
            return None
        return {
            "SampleCount": sum(d["SampleCount"] for d in dps),
            "Minimum": min(d["Minimum"] for d in dps),
            "Units": {d["Unit"] for d in dps},
        }

    post = _poll_until(
        lambda: _stats(with_ext, "PostRuntimeExtensionsDuration"),
        lambda v: v is not None and v["SampleCount"] >= _INVOKES,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"PostRuntimeExtensionsDuration for [FunctionName={with_ext}]",
    )
    assert post["Units"] == {"Milliseconds"}, f"PostRuntimeExtensionsDuration Unit(s) {post!r}"
    assert post["SampleCount"] == float(_INVOKES), (
        f"PostRuntimeExtensionsDuration SampleCount {post['SampleCount']!r}, expected {_INVOKES}"
    )
    assert post["Minimum"] >= (_EXT_HOLD_MS - _SLEEP_MS) / 2, (
        f"PostRuntimeExtensionsDuration Minimum {post['Minimum']!r} ms; the extension holds every "
        f"invoke {_EXT_HOLD_MS} ms against a {_SLEEP_MS} ms handler"
    )
    dur = _poll_until(
        lambda: _stats(with_ext, "Duration"),
        lambda v: v is not None and v["SampleCount"] >= _INVOKES,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"Duration for [FunctionName={with_ext}]",
    )
    assert dur["Minimum"] >= _SLEEP_MS + post["Minimum"] - 0.01, (
        f"Duration Minimum {dur['Minimum']!r} ms for {with_ext} does not include the post-runtime "
        f"extension time (handler {_SLEEP_MS} ms + post-runtime minimum {post['Minimum']!r} ms)"
    )

    # The twin: same code, no layer. Its ordinary series arrive, and the extension series never does.
    plain_inv = _poll_until(
        lambda: _sum(cw, "Invocations", [("FunctionName", plain)], start),
        lambda v: v is not None and v >= _INVOKES,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"Invocations for the extension-less twin {plain}",
    )
    assert plain_inv == float(_INVOKES), f"Invocations Sum for {plain} is {plain_inv!r}"
    _assert_stays(
        lambda: _stats(plain, "PostRuntimeExtensionsDuration"),
        None,
        hold_s=_ABSENCE_HOLD_S,
        description=f"PostRuntimeExtensionsDuration for the extension-less twin {plain}",
    )
    # Positive control after the absence window: the extension series is still served.
    again = _stats(with_ext, "PostRuntimeExtensionsDuration")
    assert again is not None and again["SampleCount"] == float(_INVOKES), (
        f"PostRuntimeExtensionsDuration for {with_ext} re-read as {again!r}"
    )


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test are
    published by the Lambda service, not by the function, and a role that cannot create a log
    group means the check leaves no /aws/lambda/<fn> group behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mlam-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _function(ctx, lam, role_arn: str, label: str, **extra) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-mlam-{label}-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda"},
                **extra,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateFunction {name} kept refusing the fresh role for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _reap_log_group(logs, group: str) -> None:
    """delete_function leaves the log group, and a late flush can recreate it — so delete in a
    bounded loop until a quiet read confirms it is gone."""
    from botocore.exceptions import ClientError

    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after deletion")


def _series(cw, metric: str, dims: list[tuple[str, str]], start, stats: list[str]) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=stats,
    )["Datapoints"]


def _sum(cw, metric: str, dims: list[tuple[str, str]], start) -> float | None:
    dps = _series(cw, metric, dims, start, ["Sum"])
    return float(sum(d["Sum"] for d in dps)) if dps else None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=10.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
