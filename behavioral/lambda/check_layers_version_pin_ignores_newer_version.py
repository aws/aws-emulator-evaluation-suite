"""layers-version-pin-ignores-newer-version."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layers-version-pin-ignores-newer-version"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    import sim2real_pinned as mod

    print("LAYERPIN " + mod.stamp())
    return {"token": mod.TOKEN, "stamp": mod.stamp(), "mod_file": mod.__file__}
"""


@tags("cap:c3", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A function's layer reference is pinned to the VERSION it names: publishing a newer version of
    the same layer never changes what the handler imports, and repointing to it does.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    token_v1 = uuid.uuid4().hex
    token_v2 = uuid.uuid4().hex
    assert token_v1 != token_v2, f"the two layer tokens must differ, both were {token_v1!r}"

    role_arn = _create_execution_role(ctx, iam)
    layer_name = ctx.unique_name("sim2real-behav-layers-pin-")
    v1_arn, v1_num = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_pinned.py": _layer_module(token_v1)}
    )
    assert v1_num == 1, (
        f"the first version published under the fresh layer name {layer_name!r} must be version 1, "
        f"PublishLayerVersion returned {v1_num!r}"
    )

    fn = ctx.unique_name("sim2real-behav-layers-pin-fn-")
    _reap_log_group(ctx, fn)
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[v1_arn],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    stamp_v1 = _expected_stamp(token_v1)
    stamp_v2 = _expected_stamp(token_v2)

    first = _invoke_json(lam, fn, {})
    assert first["stamp"] == stamp_v1, (
        f"the handler must import version 1's module and run its stamp() (expected {stamp_v1!r}); "
        f"Invoke returned {first!r}"
    )
    logged = _wait_for_log_line(ctx, fn, f"LAYERPIN {stamp_v1}")
    assert stamp_v1 in logged, (
        f"expected the handler's stdout line 'LAYERPIN {stamp_v1}' in /aws/lambda/{fn}; the "
        f"matched event was {logged!r}"
    )

    # ---- publish a NEWER version of the same layer; touch nothing on the function ----
    v2_arn, v2_num = _publish_layer(
        ctx, lam, layer_name, {"python/sim2real_pinned.py": _layer_module(token_v2)}
    )
    assert v2_num == 2, (
        f"the second version of {layer_name!r} must be version 2, got {v2_num!r}"
    )
    assert v2_arn != v1_arn, f"the two version ARNs must differ, both were {v1_arn!r}"

    # A MemorySize change replaces the execution environment without touching Layers, so the next
    # invocation re-resolves /opt from scratch and warm reuse cannot explain the answer.
    lam.update_function_configuration(FunctionName=fn, MemorySize=192)
    _wait_last_update_successful(lam, fn)
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert cfg["MemorySize"] == 192, (
        f"the forced-cold-start update must have landed; MemorySize is {cfg['MemorySize']!r}"
    )
    assert [ly["Arn"] for ly in cfg.get("Layers", [])] == [v1_arn], (
        f"the function must still reference version 1 exactly; GetFunctionConfiguration reports "
        f"{cfg.get('Layers')!r}"
    )

    pinned = _invoke_json(lam, fn, {})
    assert pinned["stamp"] == stamp_v1, (
        f"after publishing version 2 and forcing a new execution environment, the handler must "
        f"still import version 1's bytes (expected stamp {stamp_v1!r}); got {pinned!r}"
    )
    assert pinned["token"] != token_v2, (
        f"the newer version's token must NOT be observable while the function references "
        f"version 1; the handler returned {pinned['token']!r}"
    )

    # ---- repoint to version 2: the same import must now resolve to the new bytes ----
    lam.update_function_configuration(FunctionName=fn, Layers=[v2_arn])
    _wait_last_update_successful(lam, fn)
    repointed = _invoke_json(lam, fn, {})
    assert repointed["stamp"] == stamp_v2, (
        f"after repointing Layers to {v2_arn} the handler must import version 2's module "
        f"(expected stamp {stamp_v2!r}); got {repointed!r}"
    )
    assert repointed["mod_file"] == "/opt/python/sim2real_pinned.py", (
        f"the module must still resolve from the layer's extracted copy, not the function package; "
        f"__file__ was {repointed['mod_file']!r}"
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


def _expected_stamp(token: str) -> str:
    return f"{token}:{sum(c.isdigit() for c in token) % 10}"


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
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    arn = published["LayerVersionArn"]
    assert arn, f"PublishLayerVersion returned no LayerVersionArn for {layer_name!r}: {published!r}"
    return arn, version


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
