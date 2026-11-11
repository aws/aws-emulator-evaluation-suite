"""concurrent-lambda-invocations-update-ssm-parameter-versioning."""

from __future__ import annotations

import concurrent.futures
import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-lambda-invocations-update-ssm-parameter-versioning"

GROUP = "shared-state"

SERVICES = ["events", "lambda", "ssm"]


def _ssm_param_arn(ctx, name: str) -> str:
    """SSM parameter ARN for a flat or hierarchical name (exactly one ``parameter/`` separator)."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ssm:{ctx.region}:{account}:parameter/{name.lstrip('/')}"


# SSM's TooManyUpdates carries an empty message, so botocore's rendering ends after the colon.
_TOO_MANY_UPDATES_MESSAGE = (
    "An error occurred (TooManyUpdates) when calling the PutParameter operation: "
)


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _classify_concurrent_write(result: dict) -> tuple[str, Any]:
    """Classify one PutParameter attempt as ("ok", version) or ("rejected", "TooManyUpdates");
    any other outcome fails the check."""
    if result.get("error"):
        payload = result.get("payload")
        error_type = payload.get("errorType") if isinstance(payload, dict) else None
        message = payload.get("errorMessage") if isinstance(payload, dict) else None
        assert error_type == "TooManyUpdates", (
            f"unexpected Lambda/SSM failure (not the TooManyUpdates guard): {result}"
        )
        assert message == _TOO_MANY_UPDATES_MESSAGE, (
            f"TooManyUpdates must carry {_TOO_MANY_UPDATES_MESSAGE!r}: {result}"
        )
        return "rejected", error_type
    payload = result.get("payload")
    assert isinstance(payload, dict) and payload.get("ok") is True, (
        f"handler did not return a successful payload: {result}"
    )
    return "ok", payload["version"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutParameter calls on one parameter from Lambda: any loser is TooManyUpdates; winners
    get distinct, contiguous versions and the parameter ends at the highest winner's version and value."""
    param_name = ctx.unique_name("param-concurrent-")
    ssm = ctx.client("ssm")
    initial_version = ssm.put_parameter(Name=param_name, Value="v0", Type="String")["Version"]
    ctx.on_cleanup(lambda: ctx.client("ssm").delete_parameter(Name=param_name))

    code = f'''
import time
import boto3
ssm = boto3.client("ssm")

def lambda_handler(event, context):
    idx = event.get("idx", 0)
    start_at = event["start_at"]
    while time.time() < start_at:
        time.sleep(0.01)
    resp = ssm.put_parameter(Name="{param_name}", Value=f"v-{{idx}}", Type="String", Overwrite=True)
    return {{"ok": True, "version": resp["Version"]}}
'''
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": ["ssm:PutParameter"],
                "Resource": _ssm_param_arn(ctx, param_name),
            }
        ],
    )

    n = 5
    # A shared start time makes the writes overlap instead of depending on thread-submission jitter.
    start_at = time.time() + 5.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        futures = [
            ex.submit(_invoke_lambda_with_retry, ctx, fn["name"], {"idx": i, "start_at": start_at})
            for i in range(n)
        ]
        results = [f.result(timeout=_budget_s(ctx, 60.0)) for f in futures]

    outcomes = [_classify_concurrent_write(r) for r in results]
    writer_by_version = {v: i for i, (kind, v) in enumerate(outcomes) if kind == "ok"}
    successes = [v for kind, v in outcomes if kind == "ok"]
    rejections = [v for kind, v in outcomes if kind == "rejected"]
    assert len(successes) + len(rejections) == n

    assert len(successes) >= 1, (
        "no concurrent writer succeeded — the parameter store looks entirely unusable, not "
        "merely contended"
    )
    assert len(set(successes)) == len(successes), (
        f"duplicate versions granted to distinct winners: {successes}"
    )
    expected = set(range(initial_version + 1, initial_version + 1 + len(successes)))
    assert set(successes) == expected, (
        f"winning writers did not claim a contiguous version range: "
        f"got {sorted(successes)}, expected {sorted(expected)}"
    )

    final = ssm.get_parameter(Name=param_name)["Parameter"]
    assert final["Version"] == max(successes), (
        "final SSM version did not reflect the last successful write"
    )
    want_value = f"v-{writer_by_version[max(successes)]}"
    assert final["Value"] == want_value, (
        f"final value {final['Value']!r} is not the value {want_value!r} written by the writer "
        f"granted version {max(successes)}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # The Handler is "lambda_function.lambda_handler"; alias a `def handler` so the function does
    # not fail with Runtime.HandlerNotFound.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The /aws/lambda/<name> log group created on first invoke survives function deletion.
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda whose execution role allows `permissions` (IAM statement fragments) plus logs.
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _invoke_lambda_with_retry(
    ctx, name: str, payload: dict | None = None, timeout_s: float = 30.0
) -> dict[str, Any]:
    """Invoke, retrying an AccessDenied FunctionError through the inline-policy propagation
    window (the role's ssm:PutParameter grant can lag the role/function becoming Active)."""
    deadline = time.monotonic() + timeout_s
    result = _invoke_lambda(ctx, name, payload)
    while result.get("error") and "AccessDenied" in str(
        result.get("payload") or result.get("payload_raw") or ""
    ):
        if time.monotonic() >= deadline:
            return result
        time.sleep(2)
        result = _invoke_lambda(ctx, name, payload)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
