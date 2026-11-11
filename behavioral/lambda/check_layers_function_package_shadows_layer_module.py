"""layers-function-package-shadows-layer-module."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-function-package-shadows-layer-module"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
import sys


def handler(event, context):
    import sim2real_shadowed as mod

    print("LAYERSHADOW " + mod.stamp())
    return {
        "token": mod.TOKEN,
        "stamp": mod.stamp(),
        "mod_file": mod.__file__,
        "syspath": list(sys.path),
    }
"""


@tags("cap:c3", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """When the function package and an attached layer both provide the same module name, the
    function's own copy wins — and deleting it from the package makes the identical import fall
    through to the layer's copy.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    layer_token = uuid.uuid4().hex
    task_token = uuid.uuid4().hex
    assert layer_token != task_token, (
        f"the layer and package tokens must differ, both were {layer_token!r}"
    )

    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-shadow-")
    layer_arn = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_shadowed.py": _layer_module(layer_token)}
    )

    fn = ctx.unique_name("sim2real-behav-layers-shadow-fn-")
    _reap_log_group(ctx, fn)
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({
            "index.py": _HANDLER,
            "sim2real_shadowed.py": _layer_module(task_token),
        })},
        Layers=[layer_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    task_stamp = _expected_stamp(task_token)
    layer_stamp = _expected_stamp(layer_token)

    # ---- the effect: the PACKAGE copy is what the handler imports and executes ----
    shadowed = _invoke_json(lam, fn, {})
    assert shadowed["stamp"] == task_stamp, (
        f"with both the package and the layer providing sim2real_shadowed, the handler must import "
        f"the package's copy and run its stamp() (expected {task_stamp!r}); Invoke returned "
        f"{shadowed!r}"
    )
    assert shadowed["mod_file"] == "/var/task/sim2real_shadowed.py", (
        f"the winning module must be the one in the deployment package; __file__ was "
        f"{shadowed['mod_file']!r}"
    )
    syspath = shadowed["syspath"]
    assert "/var/task" in syspath and "/opt/python" in syspath, (
        f"both the task root and the layer root must be on sys.path; the handler saw {syspath!r}"
    )
    assert syspath.index("/var/task") < syspath.index("/opt/python"), (
        f"/var/task must PRECEDE /opt/python on sys.path — that ordering is the whole contract; "
        f"the handler saw {syspath!r}"
    )
    logged = _wait_for_log_line(ctx, fn, f"LAYERSHADOW {task_stamp}")
    assert task_stamp in logged, (
        f"expected the handler's stdout line 'LAYERSHADOW {task_stamp}' in /aws/lambda/{fn}; the "
        f"matched event was {logged!r}"
    )

    # ---- break exactly one thing: remove the package's copy, keep the layer attached ----
    lam.update_function_code(
        FunctionName=fn, ZipFile=_make_zip({"index.py": _HANDLER}), Publish=False
    )
    _wait_last_update_successful(lam, fn)
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert [ly["Arn"] for ly in cfg.get("Layers", [])] == [layer_arn], (
        f"the code update must not have disturbed the layer reference; GetFunctionConfiguration "
        f"reports {cfg.get('Layers')!r}"
    )

    # ---- the package's precedence is ABSENT, so the same import falls through to the layer ----
    fell_through = _invoke_json(lam, fn, {})
    assert fell_through["stamp"] == layer_stamp, (
        f"with the package copy removed, the identical import must resolve to the LAYER's module "
        f"and run its stamp() (expected {layer_stamp!r}); got {fell_through!r}"
    )
    assert fell_through["mod_file"] == "/opt/python/sim2real_shadowed.py", (
        f"the module must now resolve from the layer's extracted copy; __file__ was "
        f"{fell_through['mod_file']!r}"
    )
    assert fell_through["token"] != shadowed["token"], (
        f"removing the package's copy did not change which module answered — both invocations saw "
        f"token {shadowed['token']!r}, so /var/task's precedence over /opt/python is not being "
        f"honoured"
    )


# ===== helpers =====

def _layer_module(token: str) -> str:
    """A module whose stamp() no caller can produce without running that copy's own code."""
    return (
        f'TOKEN = "{token}"\n'
        "\n"
        "\n"
        "def stamp():\n"
        '    return TOKEN + ":" + str(len([c for c in TOKEN if c.isdigit()]) % 10)\n'
    )


def _expected_stamp(token: str) -> str:
    return f"{token}:{sum(c.isdigit() for c in token) % 10}"


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _publish_layer(ctx, lam, layer_name: str, files: dict[str, str]) -> str:
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip(files)},
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
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(lam, name))
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
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
    """Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.

    delete_function does not remove /aws/lambda/<fn>, and a stream buffered by an invocation that
    already returned can flush after the delete and RECREATE the group — so one delete is one
    round, not a teardown.
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
