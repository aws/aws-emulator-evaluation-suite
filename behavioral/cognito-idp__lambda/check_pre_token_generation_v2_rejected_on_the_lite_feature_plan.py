"""pre-token-generation-v2-rejected-on-the-lite-feature-plan."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pre-token-generation-v2-rejected-on-the-lite-feature-plan"
GROUP = "token-customization"
SERVICES = ["cognito-idp", "iam", "lambda", "logs"]

_PREFIX = "sim2real-cip-tier-"

_TRIGGER_CODE = """
def handler(event, context):
    event.setdefault("response", {})
    return event
"""


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserPool refuses a V2_0 PreTokenGenerationConfig on a LITE-feature-plan pool with the
    same Lambda that V1_0 accepts, and accepts V2_0 once the pool is raised to ESSENTIALS.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    """
    cog = ctx.client("cognito-idp")
    trigger_arn = _create_trigger_function(ctx)["arn"]

    pool_id = cog.create_user_pool(
        PoolName=ctx.unique_name(f"{_PREFIX}pool-"),
        UserPoolTier="LITE",
        UserPoolTags={"sim2real": "pre-token-generation-v2-rejected-on-lite"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    # Positive control: the same Lambda, as a V1_0 trigger, is accepted on this LITE pool.
    cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V1_0",
                                                   "LambdaArn": trigger_arn}},
    )
    after_v1 = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert after_v1["PreTokenGenerationConfig"]["LambdaVersion"] == "V1_0", (
        f"the LITE-plan pool did not accept the V1_0 trigger it is supposed to support: "
        f"{after_v1!r}"
    )

    code, message = _error_code(lambda: cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V2_0",
                                                   "LambdaArn": trigger_arn}},
    ))
    assert (code, message) == (
        "FeatureUnavailableInTierException",
        "The following features need to be disabled for the LITE pricing tier configured: "
        "Token Customization with Pre-Token Generation Lambda V2_0",
    ), f"unexpected refusal for V2_0 on a LITE-plan pool: {(code, message)!r}"

    unchanged = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert unchanged["PreTokenGenerationConfig"]["LambdaVersion"] == "V1_0", (
        f"the refused V2_0 update still changed the pool's LambdaConfig: {unchanged!r}"
    )

    # Restore: raise the pool to ESSENTIALS and retry the identical V2_0 update, which now
    # succeeds -- pinning the refusal to the feature plan, not to the Lambda or the version value.
    cog.update_user_pool(UserPoolId=pool_id, UserPoolTier="ESSENTIALS")
    cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V2_0",
                                                   "LambdaArn": trigger_arn}},
    )
    after_v2 = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert after_v2["PreTokenGenerationConfig"]["LambdaVersion"] == "V2_0", (
        f"the identical V2_0 update did not take effect once the pool plan was raised: "
        f"{after_v2!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last seen {last!r}")


def _make_execution_role(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"{_PREFIX}role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                          "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                     "logs:PutLogEvents"],
                          "Resource": "arn:aws:logs:*:*:*"}],
        }),
    )
    return {"name": role_name, "arn": created["Role"]["Arn"]}


def _delete_role(iam, role_name: str) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_trigger_function(ctx) -> dict[str, str]:
    """Create a Lambda never actually invoked in this check -- only its ARN is needed, to
    isolate the refusal to the pool's feature plan rather than to a missing function."""
    role = _make_execution_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"{_PREFIX}fn-")
    code = textwrap.dedent(_TRIGGER_CODE)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role["arn"],
        "Handler": "lambda_function.handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": 15, "MemorySize": 128,
        "Tags": {"sim2real": "pre-token-generation-v2-rejected-on-lite"},
    }
    deadline = time.monotonic() + 60.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            _poll_until(lambda: lam.get_function_configuration(FunctionName=name),
                       lambda r: r.get("State") == "Active", timeout_s=90.0, interval_s=2.0,
                       description=f"Lambda {name} Active")
            return {"name": name, "arn": created["FunctionArn"]}
        except ClientError as exc:
            if "cannot be assumed" in str(exc) or exc.response["Error"]["Code"] == (
                "InvalidParameterValueException"
            ):
                last_err = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not create trigger function {name}: {last_err!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    consecutive_absent = 0
    while consecutive_absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            consecutive_absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            consecutive_absent += 1
        if consecutive_absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still reappearing after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
