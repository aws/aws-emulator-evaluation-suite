"""layers-deleted-version-still-resolves-new-reference-rejected."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-deleted-version-still-resolves-new-reference-rejected"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    import sim2real_deleted as mod

    print("LAYERDEL " + mod.stamp())
    return {"token": mod.TOKEN, "stamp": mod.stamp(), "mod_file": mod.__file__}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A deleted layer version keeps resolving for the function that already references it, across a
    forced cold start, while a new function referencing the deleted ARN is refused with
    InvalidParameterValueException; a new function on a live version imports it.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    token = uuid.uuid4().hex
    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-del-")
    doomed_arn, doomed_version = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_deleted.py": _layer_module(token)}
    )

    fn = ctx.unique_name("sim2real-behav-layers-del-fn-")
    _reap_log_group(ctx, fn)
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[doomed_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    stamp = _expected_stamp(token)
    before = _invoke_json(lam, fn, {})
    assert before["stamp"] == stamp, (
        f"before the delete, the handler must import the layer's module and run its stamp() "
        f"(expected {stamp!r}); Invoke returned {before!r}"
    )
    logged = _wait_for_log_line(ctx, fn, f"LAYERDEL {stamp}")
    assert stamp in logged, (
        f"expected the handler's stdout line 'LAYERDEL {stamp}' in /aws/lambda/{fn}; the matched "
        f"event was {logged!r}"
    )

    lam.delete_layer_version(LayerName=layer_name, VersionNumber=doomed_version)
    remaining = _list_layer_versions(lam, layer_name)
    assert doomed_version not in remaining, (
        f"version {doomed_version} must be gone from ListLayerVersions({layer_name!r}) after the "
        f"delete; the versions still listed were {sorted(remaining)!r}"
    )

    # A MemorySize change replaces the execution environment, so the next invocation re-resolves
    # /opt from scratch and warm reuse cannot explain a still-working import.
    lam.update_function_configuration(FunctionName=fn, MemorySize=192)
    _wait_last_update_successful(lam, fn)
    after = _invoke_json(lam, fn, {})
    assert after["stamp"] == stamp, (
        f"the already-attached function must keep importing the deleted version's bytes after a "
        f"forced cold start (expected stamp {stamp!r}); got {after!r}"
    )
    assert after["mod_file"] == "/opt/python/sim2real_deleted.py", (
        f"the module must still resolve from the layer's extracted copy under /opt/python; "
        f"__file__ was {after['mod_file']!r}"
    )

    doomed_consumer = ctx.unique_name("sim2real-behav-layers-del-new-")
    code, message = _error(
        lambda: lam.create_function(
            FunctionName=doomed_consumer,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
            Layers=[doomed_arn],
            MemorySize=128,
            Timeout=30,
            Tags={"sim2real": CHECK},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"CreateFunction referencing the deleted layer version {doomed_arn} must be rejected with "
        f"InvalidParameterValueException; got {code!r}"
    )
    assert message == f"Layer version {doomed_arn} does not exist.", (
        f"unexpected message for CreateFunction referencing the deleted layer version: {message!r}"
    )
    gone, gone_msg = _error(lambda: lam.get_function(FunctionName=doomed_consumer))
    assert gone == "ResourceNotFoundException", (
        f"the rejected CreateFunction must have left no function behind; GetFunction("
        f"{doomed_consumer!r}) answered {gone!r}"
    )
    expected_gone = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{doomed_consumer}"
    )
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    live_token = uuid.uuid4().hex
    live_arn, _ = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_deleted.py": _layer_module(live_token)}
    )
    consumer = ctx.unique_name("sim2real-behav-layers-del-ok-")
    _reap_log_group(ctx, consumer)
    _create_function(
        ctx, lam,
        FunctionName=consumer,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[live_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, consumer)
    live = _invoke_json(lam, consumer, {})
    assert live["stamp"] == _expected_stamp(live_token), (
        f"a new function referencing the LIVE layer version {live_arn} must import its module "
        f"(expected stamp {_expected_stamp(live_token)!r}); got {live!r}"
    )


def _layer_module(token: str) -> str:
    """A module whose stamp() no caller can produce without running the layer's own code."""
    return (
        f'TOKEN = "{token}"\n'
        "\n"
        "\n"
        "def stamp():\n"
        '    return TOKEN + ":" + str(len([c for c in TOKEN if c.isdigit()]) % 10)\n'
    )


def _expected_stamp(token: str) -> str:
    return f"{token}:{sum(c.isdigit() for c in token) % 10}"


def _error(fn):
    """The AWS error (code, message) of a call expected to fail; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _publish_layer(ctx, lam, layer_name: str, files: dict[str, str]) -> tuple[str, int]:
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip(files)},
        CompatibleRuntimes=["python3.12"],
        Description=f"sim2real {CHECK}",
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: _delete_layer_version(lam, layer_name, version))
    arn = published["LayerVersionArn"]
    assert arn, f"PublishLayerVersion returned no LayerVersionArn for {layer_name!r}: {published!r}"
    return arn, version


def _delete_layer_version(lam, layer_name: str, version: int) -> None:
    """Idempotent: this check deletes one version itself, so teardown must tolerate its absence."""
    try:
        lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _list_layer_versions(lam, layer_name: str) -> set[int]:
    """Every version number ListLayerVersions reports for *layer_name*, across all pages."""
    versions: set[int] = set()
    paginator = lam.get_paginator("list_layer_versions")
    for page in paginator.paginate(LayerName=layer_name):
        for entry in page.get("LayerVersions", []):
            versions.add(entry["Version"])
    return versions


def _create_execution_role(ctx, iam) -> str:
    """This check's own execution role — nothing pre-existing in the account is assumed."""
    role_name = ctx.unique_name("sim2real-behav-layers-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # IAM propagation exposes no condition to poll; the bounded retry in _create_function covers it.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(lam, name))
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last}")


def _delete_function(lam, name: str) -> None:
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _reap_log_group(ctx, fn: str) -> None:
    """Registered before the function exists, so LIFO cleanup runs it after delete_function.

    A buffered stream can flush after the delete and recreate the group, so deletes repeat.
    """
    group = f"/aws/lambda/{fn}"

    def _reap() -> None:
        logs = ctx.client("logs")
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
            time.sleep(5)
            described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if not any(g["logGroupName"] == group for g in described):
                return
        raise RuntimeError(
            f"log group {group} kept reappearing within 60s of repeated deletes"
        )

    ctx.on_cleanup(_reap)


def _invoke_json(lam, fn: str, payload: dict) -> dict:
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"{fn} raised instead of returning a payload for {payload!r}: "
        f"{resp.get('FunctionError')} {body[:400]}"
    )
    assert resp["StatusCode"] == 200, f"Invoke returned StatusCode {resp['StatusCode']}: {body[:400]}"
    return json.loads(body)


def _wait_for_log_line(ctx, fn: str, needle: str, timeout_s: float = 150.0) -> str:
    """Poll the function's own log group for a line the HANDLER printed."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=group, filterPattern=f'"{needle}"'):
                for event in page.get("events", []):
                    if needle in event.get("message", ""):
                        return event["message"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(3)
    raise AssertionError(
        f"the handler's stdout line {needle!r} never appeared in {group} within {timeout_s}s"
    )


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe, lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s, interval_s=2.0, description=f"{name} reaching State=Active",
    )


def _wait_last_update_successful(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} update failed: {cfg.get('LastUpdateStatusReasonCode')} "
                f"{cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active",
        timeout_s=timeout_s, interval_s=2.0,
        description=f"{name} reaching LastUpdateStatus=Successful",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
