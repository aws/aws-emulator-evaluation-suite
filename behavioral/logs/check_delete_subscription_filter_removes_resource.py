"""delete-subscription-filter-removes-resource."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "delete-subscription-filter-removes-resource"
GROUP = "subscription-filters"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter creates a filter visible in DescribeSubscriptionFilters;
    DeleteSubscriptionFilter removes it so it is no longer listed."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"

    function_arn = _create_minimal_lambda(ctx, log_group_arn)

    filter_name = ctx.unique_name("sim2real-behav-sf-")
    ctx.on_cleanup(
        lambda: _ignore_notfound(
            lambda: logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
        )
    )
    _put_subscription_filter_with_retry(
        logs,
        log_group_name=log_group_name,
        filter_name=filter_name,
        function_arn=function_arn,
    )

    filters = logs.describe_subscription_filters(logGroupName=log_group_name)["subscriptionFilters"]
    names = [f["filterName"] for f in filters]
    assert filter_name in names, f"expected {filter_name} in {names} right after PutSubscriptionFilter"

    logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)

    filters_after = logs.describe_subscription_filters(logGroupName=log_group_name)["subscriptionFilters"]
    names_after = [f["filterName"] for f in filters_after]
    assert filter_name not in names_after, f"expected {filter_name} removed, still present in {names_after}"

    try:
        result = logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
    except Exception as exc:  # noqa: BLE001
        error = getattr(exc, "response", {}).get("Error", {})
    else:
        raise AssertionError(
            f"expected re-deleting the already-removed filter {filter_name} to be rejected, "
            f"but it succeeded: {result!r}"
        )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected re-deleting the already-removed filter {filter_name} to raise "
        f"ResourceNotFoundException, got {error!r}"
    )
    expected_message = "The specified subscription filter does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _put_subscription_filter_with_retry(
    logs, *, log_group_name: str, filter_name: str, function_arn: str, timeout: float = 60.0
) -> None:
    """PutSubscriptionFilter test-invokes the destination Lambda to validate it, but the
    just-created execution role and the just-added resource-based invoke permission can take a
    few seconds to propagate through IAM/Lambda. Retry on that specific transient
    InvalidParameterException instead of failing immediately."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=log_group_name,
                filterName=filter_name,
                filterPattern="",
                destinationArn=function_arn,
            )
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            code = _error_code_from_exc(exc)
            message = str(exc)
            if code == "InvalidParameterException" and "lambda function" in message.lower():
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not put subscription filter within {timeout}s: {last_exc}")


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code not in ("ResourceNotFoundException", None):
            raise


def _error_code_from_exc(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _minimal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "index.py",
            "def handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_minimal_lambda(ctx, log_group_arn: str) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: iam.delete_role(RoleName=role_name)))

    function_name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 30
    function_arn = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _minimal_zip()},
                Timeout=5,
                Tags={"sim2real": CHECK},
            )
            function_arn = resp["FunctionArn"]
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            code = _error_code_from_exc(exc)
            if code in ("InvalidParameterValueException",):
                time.sleep(2)
                continue
            raise
    if function_arn is None:
        raise AssertionError(f"could not create lambda function in time: {last_exc}")
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: lam.delete_function(FunctionName=function_name)))

    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowCWLogsInvoke",
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=log_group_arn,
    )
    return function_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
