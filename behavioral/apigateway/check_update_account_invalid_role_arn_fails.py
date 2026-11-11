"""update-account-invalid-role-arn-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-account-invalid-role-arn-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

_CWL_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """UpdateAccount rejects a cloudwatchRoleArn naming a non-existent IAM role, keeping the old one.
    A real role trusting apigateway is accepted first, so the rejection is due to the bogus ARN."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    account_id = sts.get_caller_identity()["Account"]
    original_role = apigw.get_account().get("cloudwatchRoleArn") or ""

    role_name = ctx.unique_name("sim2real-apigw-invrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    valid_role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CWL_POLICY_ARN)
    # Cleanups run LIFO: restore the account, detach the policy, then delete the role
    # (DeleteRole on a role with an attached policy is a DeleteConflict).
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CWL_POLICY_ARN))
    ctx.on_cleanup(lambda: _restore_role(apigw, original_role))

    # Positive control. IAM role/trust propagation can take up to ~90s before API Gateway
    # accepts a fresh role, so the first attempts are retried within a bound.
    _poll_until_role_accepted(apigw, valid_role_arn, timeout_s=90)
    assert apigw.get_account().get("cloudwatchRoleArn") == valid_role_arn, (
        "the positive control did not take effect: account cloudwatchRoleArn was not the "
        "freshly-created role after UpdateAccount succeeded"
    )

    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-nonexistent-role-')}"
    err = _expect_rejection(
        lambda: apigw.update_account(
            patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": bogus_role_arn}]
        )
    )
    assert err.get("Code") == "BadRequestException", (
        f"expected BadRequestException setting cloudwatchRoleArn to a non-existent role, "
        f"got {err.get('Code')!r}"
    )
    assert err.get("Message") == (
        "The role ARN does not have required permissions configured. Please grant trust "
        "permission for API Gateway and add the required role policy."
    ), f"expected the exact unusable-role refusal message, got {err.get('Message')!r}"

    after = apigw.get_account()
    assert after.get("cloudwatchRoleArn") == valid_role_arn, (
        f"account cloudwatchRoleArn must be unchanged by the rejected update, expected "
        f"{valid_role_arn!r}, got {after.get('cloudwatchRoleArn')!r}"
    )

    # The rejection must not have wedged the account: the identical valid call still works.
    apigw.update_account(
        patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role}]
    )
    restored = apigw.get_account().get("cloudwatchRoleArn") or ""
    assert restored == original_role, (
        f"account cloudwatchRoleArn did not accept the post-rejection restore call: "
        f"expected {original_role!r}, got {restored!r}"
    )


def _restore_role(apigw, original_role: str) -> None:
    """Restore the account-global ``cloudwatchRoleArn``; replacing with ``""`` clears it."""
    deadline = time.monotonic() + 60
    while True:
        try:
            apigw.update_account(
                patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role}]
            )
            return
        except ClientError as exc:
            # UpdateAccount has a low per-account rate; a throttle here is not a verdict.
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _poll_until_role_accepted(apigw, role_arn: str, *, timeout_s: float, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = "unset"
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}]
            )
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(
        f"update_account never accepted the freshly-created, assumable role {role_arn!r} "
        f"within {timeout_s}s; last error {last_code!r}"
    )


def _expect_rejection(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        "real AWS rejects UpdateAccount with a non-existent cloudwatchRoleArn, but the "
        "update SUCCEEDED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
