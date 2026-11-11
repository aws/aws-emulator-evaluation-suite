"""register-targets-exceeding-target-group-quota-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "register-targets-exceeding-target-group-quota-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-tgquota"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A lambda target group holds one target: registering a second function fails with
    TooManyTargets and leaves the registered set unchanged, and after deregistering the first
    the second function registers successfully."""
    elbv2 = ctx.client("elbv2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = _short_name(ctx, "sim2real-tgquota-role-", 64)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=list(_TAGS)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))

    code_zip = _make_lambda_zip()
    func1_name = _short_name(ctx, "sim2real-tgquota-fn1-", 64)
    func2_name = _short_name(ctx, "sim2real-tgquota-fn2-", 64)
    func1_arn = _create_function_with_retry(lam, func1_name, role_arn, code_zip, _TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=func1_name)))
    func2_arn = _create_function_with_retry(lam, func2_name, role_arn, code_zip, _TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=func2_name)))
    for name in (func1_name, func2_name):
        _poll_until(
            lambda n=name: lam.get_function_configuration(FunctionName=n)["State"],
            lambda state: state == "Active",
            timeout_s=90.0,
            interval_s=3.0,
        )

    tg_name = _short_name(ctx, "sim2real-tgquota-", 32)
    tg_arn = elbv2.create_target_group(
        Name=tg_name, TargetType="lambda", Tags=list(_TAGS)
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    lam.add_permission(
        FunctionName=func1_name, StatementId="sim2real-elb-invoke-1", Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
    )
    lam.add_permission(
        FunctionName=func2_name, StatementId="sim2real-elb-invoke-2", Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
    )

    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": func1_arn}])
    registered_ids = lambda: {d["Target"]["Id"] for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}
    ids_after_first = registered_ids()
    assert ids_after_first == {func1_arn}, f"expected only func1 registered, got {ids_after_first}"

    code, message = _error_code(lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": func2_arn}]))
    assert code == "TooManyTargets", f"expected TooManyTargets, got {code!r}"
    assert message == f"The maximum number of targets on target group '{tg_arn}' has been reached", (
        message
    )
    ids_after_rejected = registered_ids()
    assert ids_after_rejected == {func1_arn}, (
        f"rejected RegisterTargets must not change the registered set, got {ids_after_rejected}"
    )

    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": func1_arn}])
    _poll_until(registered_ids, lambda ids: func1_arn not in ids, timeout_s=60.0, interval_s=3.0)
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": func2_arn}])
    _poll_until(registered_ids, lambda ids: func2_arn in ids, timeout_s=60.0, interval_s=3.0)
    ids_after_swap = registered_ids()
    assert ids_after_swap == {func2_arn}, f"expected only func2 registered after swap, got {ids_after_swap}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", ""), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _make_lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n",
        )
    return buf.getvalue()


def _create_function_with_retry(
    lam, func_name: str, role_arn: str, code_zip: bytes, tag_list: list[dict[str, str]]
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_zip},
                Timeout=10,
                Tags={t["Key"]: t["Value"] for t in tag_list},
            )
            return resp["FunctionArn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"lambda create_function never succeeded (IAM propagation?): {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
