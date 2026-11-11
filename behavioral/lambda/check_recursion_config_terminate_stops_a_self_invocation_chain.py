"""recursion-config-terminate-stops-a-self-invocation-chain."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recursion-config-terminate-stops-a-self-invocation-chain"
GROUP = "overly-permissive"
SERVICES = ["lambda"]

# Above the documented "approximately 16" so a working guardrail always stops first, and low enough
# that the nested synchronous chain fits inside the check-side read timeout when it does NOT.
_CHAIN_CAP = 20

# The handler self-invokes from inside the function's runtime, so it uses its own boto3 client.
_HANDLER = """\
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_LAM = boto3.client(
    "lambda", config=Config(retries={"max_attempts": 0}, read_timeout=110, connect_timeout=10)
)


def handler(event, context):
    depth = int(event.get("depth", 1))
    cap = int(event["cap"])
    if depth >= cap:
        return {"max_depth": depth, "stopped_by": "cap", "detail": ""}
    try:
        resp = _LAM.invoke(
            FunctionName=context.function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"depth": depth + 1, "cap": cap}).encode(),
        )
    except ClientError as exc:
        return {
            "max_depth": depth,
            "stopped_by": exc.response.get("Error", {}).get("Code"),
            "detail": str(exc)[:200],
        }
    body = resp["Payload"].read().decode()
    if resp.get("FunctionError"):
        return {"max_depth": depth, "stopped_by": "FunctionError", "detail": body[:200]}
    return json.loads(body)
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RecursiveLoop=Terminate stops a self-invocation chain with RecursiveInvocationException,
    while RecursiveLoop=Allow lets the identical chain run to its cap, before and after.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    fn = ctx.unique_name("sim2real-behav-recursion-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    role_arn = _create_self_invoking_role(ctx, iam, fn_arn)

    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        MemorySize=1024,
        Timeout=120,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    # Positive control: with Allow the chain reaches its own cap, so an earlier stop under
    # Terminate can only be the guardrail.
    _set_recursion(lam, fn, "Allow")
    allowed = _run_chain(lam, fn, _CHAIN_CAP)
    assert allowed["stopped_by"] == "cap", (
        f"positive control failed: with RecursiveLoop=Allow the chain must run to its cap and stop "
        f"itself, but it stopped at depth {allowed['max_depth']} because "
        f"{allowed['stopped_by']!r}: {allowed.get('detail')!r}"
    )
    assert allowed["max_depth"] == _CHAIN_CAP, (
        f"positive control failed: with Allow the chain must reach depth {_CHAIN_CAP}, it reported "
        f"{allowed['max_depth']}"
    )

    _set_recursion(lam, fn, "Terminate")
    terminated = _run_chain(lam, fn, _CHAIN_CAP)
    assert terminated["stopped_by"] == "RecursiveInvocationException", (
        f"with RecursiveLoop=Terminate the chain must be stopped with RecursiveInvocationException; "
        f"it stopped at depth {terminated['max_depth']} because {terminated['stopped_by']!r}: "
        f"{terminated.get('detail')!r}"
    )

    # Docs say the guardrail fires at approximately 16 invocations, so assert a band, not 16.
    depth = terminated["max_depth"]
    assert depth < _CHAIN_CAP, (
        f"the chain reached its cap of {_CHAIN_CAP} even with RecursiveLoop=Terminate, so nothing "
        f"was withheld (stopped_by={terminated['stopped_by']!r})"
    )
    assert depth >= 8, (
        f"the guardrail fired at depth {depth}, far below the documented 'approximately 16' "
        f"invocations in one request chain — this looks like every self-invoke being refused rather "
        f"than a loop being detected"
    )

    _set_recursion(lam, fn, "Allow")
    reallowed = _run_chain(lam, fn, _CHAIN_CAP)
    assert reallowed["stopped_by"] == "cap" and reallowed["max_depth"] == _CHAIN_CAP, (
        f"after restoring RecursiveLoop=Allow the identical chain must reach depth {_CHAIN_CAP} "
        f"again; it stopped at {reallowed['max_depth']} because {reallowed['stopped_by']!r}: "
        f"{reallowed.get('detail')!r}"
    )
    assert reallowed["max_depth"] > depth, (
        f"restoring Allow did not lift the guardrail: the chain still stopped at depth "
        f"{reallowed['max_depth']}, no deeper than the Terminate leg's {depth}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _set_recursion(lam, fn: str, value: str) -> None:
    put = lam.put_function_recursion_config(FunctionName=fn, RecursiveLoop=value)
    assert put.get("RecursiveLoop") == value, (
        f"PutFunctionRecursionConfig({value}) echoed {put.get('RecursiveLoop')!r}"
    )
    got = lam.get_function_recursion_config(FunctionName=fn)
    assert got.get("RecursiveLoop") == value, (
        f"GetFunctionRecursionConfig must report {value!r} after it was set, got "
        f"{got.get('RecursiveLoop')!r}"
    )


def _run_chain(lam, fn: str, cap: int) -> dict:
    """Start one request chain and return the deepest level's report."""
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps({"depth": 1, "cap": cap}).encode(),
    )
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"the OUTERMOST invocation of {fn} raised instead of reporting the chain result: "
        f"{resp.get('FunctionError')} {body[:300]}"
    )
    assert resp["StatusCode"] == 200, (
        f"Invoke({fn}) returned StatusCode {resp['StatusCode']}: {body[:300]}"
    )
    parsed = json.loads(body)
    for key in ("max_depth", "stopped_by"):
        if key not in parsed:
            raise AssertionError(f"chain report is missing {key!r}: {parsed!r}")
    return parsed


def _create_self_invoking_role(ctx, iam, fn_arn: str) -> str:
    """Execution role granted lambda:InvokeFunction on this one function so the handler can
    self-invoke."""
    role_name = ctx.unique_name("sim2real-behav-recursion-role-")
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

    inline = "self-invoke"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))
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
