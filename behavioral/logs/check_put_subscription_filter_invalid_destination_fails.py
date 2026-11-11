"""put-subscription-filter-invalid-destination-fails."""
from __future__ import annotations

import json
import time
import zipfile
import io

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_minimal_function(ctx) -> str:
    """Create a minimal Lambda subscription-filter destination and return its ARN."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-psfid-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
    zip_bytes = buf.getvalue()

    function_name = ctx.unique_name("sim2real-behav-psfid-fn-")
    deadline = time.monotonic() + 30.0
    last_err = None
    function_arn = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
            )
            function_arn = resp["FunctionArn"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(1.5)
                continue
            raise
    if function_arn is None:
        raise AssertionError(f"could not create lambda function: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return function_arn


def _grant_logs_invoke_permission(ctx, function_arn: str, log_group_name: str) -> None:
    """Grant CloudWatch Logs permission to invoke the Lambda function as a
    subscription-filter destination, scoped to this specific log group."""
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    function_name = function_arn.split(":")[-1]
    statement_id = ctx.unique_name("sim2real-behav-psfid-perm-")
    account_id = sts.get_caller_identity()["Account"]
    source_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=source_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id)
    )


def _put_filter_with_retry(logs, group_name: str, filter_name: str, destination_arn: str) -> None:
    """Retry InvalidParameterException while the new Lambda resource policy propagates."""
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=group_name,
                filterName=filter_name,
                filterPattern="",
                destinationArn=destination_arn,
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidParameterException":
                last_err = err
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not put subscription filter in time: {last_err}")


CHECK = "put-subscription-filter-invalid-destination-fails"
GROUP = 'subscription-filters'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter with a malformed destination ARN fails with InvalidParameterException
    and persists nothing, while a real Lambda destination on the same log group succeeds.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-sub-baddest-")
    good_filter_name = ctx.unique_name("sim2real-behav-subfilter-good-")
    bad_filter_name = ctx.unique_name("sim2real-behav-subfilter-bad-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    function_arn = _create_minimal_function(ctx)
    _grant_logs_invoke_permission(ctx, function_arn, group)
    _put_filter_with_retry(svc, group, good_filter_name, function_arn)
    ctx.on_cleanup(
        lambda: svc.delete_subscription_filter(logGroupName=group, filterName=good_filter_name)
    )
    filters = svc.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    assert any(f["filterName"] == good_filter_name for f in filters), (
        f"positive control: expected {good_filter_name!r} among {filters!r}"
    )

    # AWS does not check that a well-formed same-account Kinesis ARN exists; use a malformed one.
    code, message = _client_error(
        lambda: svc.put_subscription_filter(
            logGroupName=group,
            filterName=bad_filter_name,
            filterPattern="",
            destinationArn="not-an-arn",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "1 validation error detected: Unable to parse destinationArn not-an-arn", (
        f"unexpected message: {message!r}"
    )

    filters = svc.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    names = {f["filterName"] for f in filters}
    assert bad_filter_name not in names, f"malformed-destination filter persisted: {filters!r}"
    assert good_filter_name in names, f"positive control filter vanished: {filters!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
