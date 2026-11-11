"""layers-bin-on-path-executes-layer-binary."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-bin-on-path-executes-layer-binary"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_TOOL_NAME = "sim2real-layer-tool"

_HANDLER = f"""\
import os
import shutil
import subprocess

TOOL = {_TOOL_NAME!r}


def handler(event, context):
    if event.get("mode") == "probe":
        return {{
            "path": os.environ.get("PATH", ""),
            "opt_bin_exists": os.path.isdir("/opt/bin"),
            "resolved": shutil.which(TOOL),
        }}
    try:
        done = subprocess.run([TOOL], capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return {{
            "ran": False,
            "error_type": type(exc).__name__,
            "path": os.environ.get("PATH", ""),
            "resolved": shutil.which(TOOL),
        }}
    print("LAYERBIN " + done.stdout.strip())
    return {{
        "ran": True,
        "returncode": done.returncode,
        "stdout": done.stdout.strip(),
        "stderr": done.stderr.strip()[-200:],
        "path": os.environ.get("PATH", ""),
        "resolved": shutil.which(TOOL),
        "opt_bin": sorted(os.listdir("/opt/bin")),
    }}
"""


@tags("cap:c3", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A layer's bin/ entry lands under /opt/bin on PATH and runs by bare name from the handler,
    which logs its token; detaching the layer makes the same exec fail with FileNotFoundError.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    token = uuid.uuid4().hex
    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-bin-")
    layer_arn = _publish_layer(
        ctx, lam, layer_name,
        executables={f"bin/{_TOOL_NAME}": f'#!/bin/sh\necho "{token}"\n'},
    )

    fn = ctx.unique_name("sim2real-behav-layers-bin-fn-")
    _reap_log_group(ctx, fn)
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[layer_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    ran = _invoke_json(lam, fn, {"mode": "exec"})
    assert ran["ran"] is True, (
        f"the handler must have been able to exec {_TOOL_NAME!r} from the attached layer; it "
        f"reported {ran!r}"
    )
    assert ran["returncode"] == 0, (
        f"the layer's script must exit 0; returncode {ran['returncode']!r}, stderr "
        f"{ran['stderr']!r}"
    )
    assert ran["stdout"] == token, (
        f"the layer script's stdout must be the token {token!r} that only its own bytes carry; "
        f"got {ran['stdout']!r}"
    )
    assert ran["resolved"] == f"/opt/bin/{_TOOL_NAME}", (
        f"the bare command name must resolve to the layer's extracted copy under /opt/bin; "
        f"shutil.which returned {ran['resolved']!r} with PATH={ran['path']!r}"
    )
    assert "/opt/bin" in ran["path"].split(":"), (
        f"/opt/bin must be a PATH element in the execution environment, which is what makes a "
        f"layer-provided command runnable by name; PATH was {ran['path']!r}"
    )
    assert _TOOL_NAME in ran["opt_bin"], (
        f"the layer's bin/ entry must be extracted into /opt/bin; the handler listed "
        f"{ran['opt_bin']!r}"
    )

    logged = _wait_for_log_line(ctx, fn, f"LAYERBIN {token}")
    assert token in logged, (
        f"expected the handler's stdout line 'LAYERBIN {token}' in /aws/lambda/{fn}; the matched "
        f"event was {logged!r}"
    )

    # Detach the layer with the code unchanged.
    lam.update_function_configuration(FunctionName=fn, Layers=[])
    _wait_last_update_successful(lam, fn)

    gone = _invoke_json(lam, fn, {"mode": "exec"})
    assert gone["ran"] is False, (
        f"with the layer detached the exec must fail; the handler still ran the command and got "
        f"{gone!r}"
    )
    assert gone["error_type"] == "FileNotFoundError", (
        f"the failure must be the runtime's own FileNotFoundError for the unresolvable command; "
        f"the handler reported {gone!r}"
    )
    assert gone["resolved"] is None, (
        f"{_TOOL_NAME!r} must no longer resolve on PATH once the layer is detached; "
        f"shutil.which returned {gone['resolved']!r}"
    )

    probe = _invoke_json(lam, fn, {"mode": "probe"})
    assert probe["opt_bin_exists"] is False, (
        f"/opt/bin must not exist with no layer attached; the handler reported PATH="
        f"{probe['path']!r}"
    )

    lam.update_function_configuration(FunctionName=fn, Layers=[layer_arn])
    _wait_last_update_successful(lam, fn)
    restored = _invoke_json(lam, fn, {"mode": "exec"})
    assert restored["stdout"] == token, (
        f"re-attaching {layer_arn} must make the layer's command runnable again and print "
        f"{token!r}; got {restored!r}"
    )


def _make_zip(files: dict[str, str], executables: dict[str, str] | None = None) -> bytes:
    """Zip writer that sets the 0o755 external attributes Lambda preserves on extraction."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
        for name, content in (executables or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o100755 << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
    return buf.getvalue()


def _publish_layer(ctx, lam, layer_name: str, *, files: dict[str, str] | None = None,
                   executables: dict[str, str] | None = None) -> str:
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip(files or {}, executables)},
        CompatibleRuntimes=["python3.12"],
        Description=f"sim2real {CHECK}",
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    arn = published["LayerVersionArn"]
    assert arn, f"PublishLayerVersion returned no LayerVersionArn for {layer_name!r}: {published!r}"
    return arn


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
    # IAM propagation is absorbed at first use by the deadline-bound retry in _create_function.
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
            time.sleep(2)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last}")


def _delete_function(lam, name: str) -> None:
    lam.delete_function(FunctionName=name)


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
