"""put-subscription-filter-exceeds-quota-rejected."""
from __future__ import annotations

import json
import time
import zipfile
import io

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-subscription-filter-exceeds-quota-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

# Each log group can have up to two subscription filters associated with it, per
# https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html
_QUOTA = 2


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter rejects the first over-quota filter with LimitExceededException and
    does not attach it; deleting one accepted filter lets the identical call succeed.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-psfq-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    function_arn = _create_minimal_function(ctx)
    _grant_logs_invoke_permission(ctx, function_arn, group_name)

    # Add filters until one is rejected; the documented quota is 2, so 10 bounds the loop.
    _MAX_PROBE = 10
    accepted_names = []
    overflow_code = None
    overflow_message = None
    overflow_name = None
    for i in range(_MAX_PROBE):
        name = ctx.unique_name(f"filter-{i}-")
        try:
            _put_filter_with_retry(logs, group_name, name, function_arn)
            accepted_names.append(name)
        except ClientError as err:
            overflow_code = err.response["Error"]["Code"]
            overflow_message = err.response["Error"].get("Message")
            overflow_name = name
            break

    assert overflow_code is not None, (
        f"expected an over-quota rejection within {_MAX_PROBE} filters, but all succeeded"
    )
    assert overflow_code == "LimitExceededException", f"GOT={overflow_code}"
    assert overflow_message == "Resource limit exceeded.", f"GOT={overflow_message!r}"
    assert len(accepted_names) >= 1, "expected at least 1 filter to be accepted before quota hit"

    attached = {
        f["filterName"]
        for f in logs.describe_subscription_filters(logGroupName=group_name)["subscriptionFilters"]
    }
    assert attached == set(accepted_names), f"unexpected attached filters: {attached}"
    assert overflow_name not in attached

    assert len(attached) == len(accepted_names)

    freed_name = accepted_names[0]
    logs.delete_subscription_filter(logGroupName=group_name, filterName=freed_name)
    _put_filter_with_retry(logs, group_name, overflow_name, function_arn)

    attached_after_restore = {
        f["filterName"]
        for f in logs.describe_subscription_filters(logGroupName=group_name)["subscriptionFilters"]
    }
    assert overflow_name in attached_after_restore, (
        f"expected {overflow_name} to succeed once capacity was freed, "
        f"got attached={attached_after_restore}"
    )
    assert freed_name not in attached_after_restore, (
        f"expected deleted filter {freed_name} to be gone, got attached={attached_after_restore}"
    )



def _grant_logs_invoke_permission(ctx, function_arn: str, log_group_name: str) -> None:
    """Grant CloudWatch Logs permission to invoke the Lambda function as a
    subscription-filter destination, scoped to this specific log group."""
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    function_name = function_arn.split(":")[-1]
    statement_id = ctx.unique_name("sim2real-behav-psfq-perm-")
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



def _put_filter_with_retry(logs, group_name: str, filter_name: str, function_arn: str) -> None:
    """Retry InvalidParameterException while the new Lambda resource policy propagates."""
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=group_name,
                filterName=filter_name,
                filterPattern="",
                destinationArn=function_arn,
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



def _create_minimal_function(ctx) -> str:
    """Create a minimal Lambda subscription-filter destination and return its ARN."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-psfq-role-")
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
        zf.writestr(
            "index.py",
            "def handler(event, context):\n    return {'ok': True}\n",
        )
    zip_bytes = buf.getvalue()

    function_name = ctx.unique_name("sim2real-behav-psfq-fn-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
