"""two-layers-sharing-a-path-resolve-to-the-last-layer-at-runtime."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "two-layers-sharing-a-path-resolve-to-the-last-layer-at-runtime"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
import os
import sys


def handler(event, context):
    import only_a
    import only_b
    import shadow

    return {
        "which": shadow.WHICH,
        "only_a": only_a.A,
        "only_b": only_b.B,
        "shadow_file": shadow.__file__,
        "opt_python": sorted(os.listdir("/opt/python")),
        "opt_on_path": [p for p in sys.path if p.startswith("/opt")],
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When two layers ship the same path, the last layer in Layers wins at runtime and reversing
    the list flips the winner, while both layers' unique files stay importable.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_execution_role(ctx, iam)

    layer_a = _publish_layer(
        ctx,
        lam,
        ctx.unique_name("sim2real-behav-shadow-a-"),
        {"python/shadow.py": 'WHICH = "layer-a"\n', "python/only_a.py": 'A = "unique-to-a"\n'},
    )
    layer_b = _publish_layer(
        ctx,
        lam,
        ctx.unique_name("sim2real-behav-shadow-b-"),
        {"python/shadow.py": 'WHICH = "layer-b"\n', "python/only_b.py": 'B = "unique-to-b"\n'},
    )
    assert layer_a != layer_b, f"the two layer ARNs must differ, both were {layer_a!r}"

    fn = ctx.unique_name("sim2real-behav-layerorder-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Layers=[layer_a, layer_b],
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    # The control plane must preserve the order it was given, not normalise it.
    ordered = [ly["Arn"] for ly in lam.get_function_configuration(FunctionName=fn)["Layers"]]
    assert ordered == [layer_a, layer_b], (
        f"GetFunctionConfiguration must echo Layers in the order supplied: expected "
        f"[{layer_a}, {layer_b}], got {ordered}"
    )

    # The runtime's own view of /opt, through Invoke, not the config echo.
    first = _invoke_json(lam, fn)
    assert first["only_a"] == "unique-to-a", (
        f"layer A's unique module must be importable with Layers=[A, B]; got {first!r}"
    )
    assert first["only_b"] == "unique-to-b", (
        f"layer B's unique module must be importable with Layers=[A, B] — layers MERGE into /opt, "
        f"the later one does not replace the earlier wholesale; got {first!r}"
    )
    assert first["which"] == "layer-b", (
        f"with Layers=[A, B] the shared path python/shadow.py must resolve to the LAST layer "
        f"(expected WHICH='layer-b'), got {first['which']!r} loaded from "
        f"{first.get('shadow_file')!r}; sys.path /opt entries were {first.get('opt_on_path')}"
    )

    # Flip the order on the same function: the winner must flip with it.
    lam.update_function_configuration(FunctionName=fn, Layers=[layer_b, layer_a])
    _wait_last_update_successful(lam, fn)
    reordered = [ly["Arn"] for ly in lam.get_function_configuration(FunctionName=fn)["Layers"]]
    assert reordered == [layer_b, layer_a], (
        f"UpdateFunctionConfiguration must store the reversed order: expected "
        f"[{layer_b}, {layer_a}], got {reordered}"
    )

    second = _invoke_json(lam, fn)
    assert second["only_a"] == "unique-to-a" and second["only_b"] == "unique-to-b", (
        f"both layers must still be merged into /opt after the reorder; got {second!r}"
    )
    assert second["which"] == "layer-a", (
        f"after reversing Layers to [B, A] the shared path must resolve to layer A "
        f"(expected WHICH='layer-a'), got {second['which']!r} loaded from "
        f"{second.get('shadow_file')!r}"
    )
    assert second["which"] != first["which"], (
        f"reversing the Layers list did not change which layer won the shared path — both "
        f"invocations saw {first['which']!r}, so extraction order is being ignored"
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
    ctx.on_cleanup(
        lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)
    )
    arn = published["LayerVersionArn"]
    assert arn, f"PublishLayerVersion returned no LayerVersionArn for {layer_name!r}: {published!r}"
    return arn


def _invoke_json(lam, fn: str) -> dict:
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=b"{}")
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"{fn} raised instead of returning its view of /opt: {resp.get('FunctionError')} {body[:300]}"
    )
    assert resp["StatusCode"] == 200, f"Invoke returned StatusCode {resp['StatusCode']}: {body[:300]}"
    parsed = json.loads(body)
    for key in ("which", "only_a", "only_b"):
        if key not in parsed:
            raise AssertionError(f"handler response is missing {key!r}: {parsed!r}")
    return parsed


def _create_execution_role(ctx, iam) -> str:
    """Create this check's execution role, tagged with the check id."""
    role_name = ctx.unique_name("sim2real-behav-layerorder-role-")
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
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
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
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
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
        timeout_s=timeout_s,
        interval_s=2.0,
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
