"""layers-detach-breaks-handler-import."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-detach-breaks-handler-import"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
import os
import sys


def handler(event, context):
    if event.get("mode") == "probe":
        return {
            "opt_entries": sorted(os.listdir("/opt")),
            "opt_python_exists": os.path.isdir("/opt/python"),
            "opt_on_syspath": [p for p in sys.path if p.startswith("/opt")],
        }
    import sim2real_layermod as mod

    print("LAYERPROOF " + mod.stamp())
    return {
        "token": mod.TOKEN,
        "stamp": mod.stamp(),
        "mod_file": mod.__file__,
        "opt_python": sorted(os.listdir("/opt/python")),
        "opt_on_syspath": [p for p in sys.path if p.startswith("/opt")],
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Detaching the only layer stops the handler importing its module, and the returned error
    payload carries the Python runtime's own ModuleNotFoundError — then re-attaching restores it.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    token = uuid.uuid4().hex
    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-detach-")
    layer_arn = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_layermod.py": _layer_module(token)}
    )

    fn = ctx.unique_name("sim2real-behav-layers-detach-fn-")
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

    # ---- the effect: the layer's module is on the import path and its code RAN ----
    attached = _invoke_json(lam, fn, {"mode": "import"})
    expected_stamp = f"{token}:{sum(c.isdigit() for c in token) % 10}"
    assert attached["token"] == token, (
        f"the handler must import TOKEN={token!r} from the attached layer's "
        f"python/sim2real_layermod.py; Invoke returned {attached!r}"
    )
    assert attached["stamp"] == expected_stamp, (
        f"the layer module's stamp() must have EXECUTED inside the handler and returned "
        f"{expected_stamp!r} (a value only that module's code can compute); got "
        f"{attached['stamp']!r}"
    )
    assert attached["mod_file"] == "/opt/python/sim2real_layermod.py", (
        f"the imported module must resolve to the layer's extracted copy under /opt/python, "
        f"not to anything in the function package; __file__ was {attached['mod_file']!r}"
    )
    assert "/opt/python" in attached["opt_on_syspath"], (
        f"/opt/python must be on the runtime's sys.path for a layer to be importable at all; "
        f"the handler saw {attached['opt_on_syspath']!r}"
    )

    # The handler's own stdout, in its log group — not a control-plane echo of the config.
    logged = _wait_for_log_line(ctx, fn, f"LAYERPROOF {expected_stamp}")
    assert expected_stamp in logged, (
        f"expected the handler's stdout line 'LAYERPROOF {expected_stamp}' in "
        f"/aws/lambda/{fn}; the matched event was {logged!r}"
    )

    # ---- break exactly one thing: detach the layer, leaving the code byte-identical ----
    lam.update_function_configuration(FunctionName=fn, Layers=[])
    _wait_last_update_successful(lam, fn)
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert cfg.get("Layers", []) == [], (
        f"after UpdateFunctionConfiguration(Layers=[]) the function must carry no layers; "
        f"GetFunctionConfiguration still reports {cfg.get('Layers')!r}"
    )

    # ---- the effect is ABSENT: the runtime's own ImportError comes back in the payload ----
    failed = _invoke_error(lam, fn, {"mode": "import"})
    assert failed["function_error"] == "Unhandled", (
        f"the detached invoke must surface FunctionError='Unhandled'; the Invoke response "
        f"reported {failed['function_error']!r} with payload {failed['payload']!r}"
    )
    assert failed["payload"].get("errorType") == "ModuleNotFoundError", (
        f"the returned error payload must carry the Python runtime's own "
        f"ModuleNotFoundError for the module the layer was providing; got {failed['payload']!r}"
    )
    assert failed["payload"].get("errorMessage") == "No module named 'sim2real_layermod'", (
        f"the errorMessage must name the layer's module exactly; got "
        f"{failed['payload'].get('errorMessage')!r}"
    )

    probe = _invoke_json(lam, fn, {"mode": "probe"})
    assert probe["opt_python_exists"] is False, (
        f"with no layer attached, /opt/python must not exist in the execution environment; the "
        f"handler listed /opt as {probe['opt_entries']!r}"
    )

    # ---- positive control, same file: re-attaching restores the import and the stamp ----
    lam.update_function_configuration(FunctionName=fn, Layers=[layer_arn])
    _wait_last_update_successful(lam, fn)
    restored = _invoke_json(lam, fn, {"mode": "import"})
    assert restored["stamp"] == expected_stamp, (
        f"re-attaching {layer_arn} must make the layer's module importable and executable again "
        f"(expected stamp {expected_stamp!r}); got {restored!r}"
    )


# ===== helpers =====

def _layer_module(token: str) -> str:
    """A module whose stamp() no caller can produce without running the layer's own code."""
    return (
        f'TOKEN = "{token}"\n'
        "\n"
        "\n"
        "def stamp():\n"
        '    return TOKEN + ":" + str(len([c for c in TOKEN if c.isdigit()]) % 10)\n'
    )


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


def _invoke_error(lam, fn: str, payload: dict) -> dict:
    """Invoke expecting the handler to raise; returns the runtime's own error payload."""
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    body = resp["Payload"].read().decode()
    if "FunctionError" not in resp:
        raise AssertionError(
            f"{fn} was expected to raise for {payload!r} but returned successfully: {body[:400]}"
        )
    return {"function_error": resp["FunctionError"], "payload": json.loads(body)}


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
