"""durable-config-defaults-and-partial-update."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-config-defaults-and-partial-update"
GROUP = "server-side"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    return {"ok": True}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _create_durable_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-durcfg-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active_or_failed(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] in ("Active", "Failed"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} did not settle within {timeout_s}s. Last: {last!r}")


def _create_durable_function(ctx, lam, *, name, role_arn, durable_config, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.13", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _make_zip(_HANDLER)},
                MemorySize=256, DurableConfig=durable_config,
            )
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "role" in str(exc).lower():
                time.sleep(3)
                continue
            raise AssertionError(f"durable functions are not available in this environment: {exc}") from exc
    raise AssertionError(f"could not create durable function after retries: {last_exc}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DurableConfig defaults RetentionPeriodInDays to 14 and Timeout to 900; a partial update keeps
    unsupplied members; a function created without DurableConfig reports None for it, not {}.
    """
    lam = ctx.client("lambda")
    role_arn = _create_durable_role(ctx)

    durable_fn = ctx.unique_name("sim2real-behav-durcfg-")
    created = _create_durable_function(
        ctx, lam, name=durable_fn, role_arn=role_arn, durable_config={"ExecutionTimeout": 3600}
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=durable_fn))

    assert created["DurableConfig"]["ExecutionTimeout"] == 3600, (
        f"ExecutionTimeout should echo the 3600 supplied at create, got {created['DurableConfig']!r}"
    )
    assert created["DurableConfig"]["RetentionPeriodInDays"] == 14, (
        f"RetentionPeriodInDays should default to 14 when omitted, got {created['DurableConfig']!r}"
    )
    assert created["Timeout"] == 900, (
        f"a durable function's own Timeout should default to the 900s (15 minute) cap, "
        f"got {created['Timeout']!r}"
    )

    settled = _wait_active_or_failed(lam, durable_fn)
    assert settled["State"] == "Active", f"durable function failed to activate: {settled.get('StateReason')}"

    updated = lam.update_function_configuration(
        FunctionName=durable_fn, DurableConfig={"RetentionPeriodInDays": 7}
    )
    assert updated["DurableConfig"]["ExecutionTimeout"] == 3600, (
        f"a DurableConfig update that supplies only RetentionPeriodInDays must leave "
        f"ExecutionTimeout at its prior value 3600, got {updated['DurableConfig']!r}"
    )
    assert updated["DurableConfig"]["RetentionPeriodInDays"] == 7, (
        f"RetentionPeriodInDays should now read back 7, got {updated['DurableConfig']!r}"
    )

    got = lam.get_function_configuration(FunctionName=durable_fn)
    assert got["DurableConfig"]["RetentionPeriodInDays"] == 7, (
        f"GetFunctionConfiguration should reflect the update, got {got['DurableConfig']!r}"
    )
    assert got["DurableConfig"]["ExecutionTimeout"] == 3600, got["DurableConfig"]

    plain_fn = ctx.unique_name("sim2real-behav-durcfg-plain-")
    lam.create_function(
        FunctionName=plain_fn, Runtime="python3.12", Handler="index.handler",
        Role=role_arn, Code={"ZipFile": _make_zip(_HANDLER)}, MemorySize=128, Timeout=10,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=plain_fn))
    plain = lam.get_function_configuration(FunctionName=plain_fn)
    assert plain.get("DurableConfig") is None, (
        f"a function created with no DurableConfig must report None for it, got {plain.get('DurableConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
