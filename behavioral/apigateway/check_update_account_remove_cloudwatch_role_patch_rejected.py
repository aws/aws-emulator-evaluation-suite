"""update-account-remove-cloudwatch-role-patch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-account-remove-cloudwatch-role-patch-rejected"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error_code(fn):
    """Call fn() and return its botocore (Code, Message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get(
            "Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded, returning {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """UpdateAccount rejects op "remove" on /cloudwatchRoleArn with BadRequestException; role kept.
    Controls show "replace" sets the role and "replace" with "" clears it; only the op is refused.
    """
    apigw = ctx.client("apigateway")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-apigw-cwrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # Registered AFTER delete_role, so LIFO runs this detach FIRST: delete_role fails
    # with DeleteConflict while a managed policy is still attached.
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    before = apigw.get_account()
    original_role = before.get("cloudwatchRoleArn", "")
    ctx.on_cleanup(lambda: apigw.update_account(
        patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role}]
    ))

    # Positive control: replace actually sets the role, observed via an independent read.
    # IAM propagation exposes no condition to poll, so a short bounded retry on the
    # validator's transient rejection stands in for one.
    deadline = time.monotonic() + 75
    while True:
        try:
            apigw.update_account(
                patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}]
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(3)
    confirmed = apigw.get_account()
    assert confirmed.get("cloudwatchRoleArn") == role_arn, (
        f"positive control: expected cloudwatchRoleArn={role_arn!r} after replace, got "
        f"{confirmed.get('cloudwatchRoleArn')!r}"
    )

    # The op under test: "remove" on the SAME path real AWS only accepts "replace" for.
    got = _error_code(
        lambda: apigw.update_account(
            patchOperations=[{"op": "remove", "path": "/cloudwatchRoleArn"}]
        )
    )
    # Real AWS's own wording, double space included: the path is valid, the op is not.
    want = ("BadRequestException",
            "Invalid patch path  '/cloudwatchRoleArn' specified for op 'remove'. "
            "Must be one of: [/cloudwatchRoleArn]")
    assert got == want, f"expected {want!r}, got {got!r}"

    # The forbidden effect did not happen: the role from the positive control survives
    # the rejected remove, observed via an independent GetAccount.
    after_reject = apigw.get_account()
    assert after_reject.get("cloudwatchRoleArn") == role_arn, (
        f"expected cloudwatchRoleArn to remain {role_arn!r} after the rejected remove, got "
        f"{after_reject.get('cloudwatchRoleArn')!r}"
    )

    # Second positive control: the actual way to clear the field is replace with "".
    apigw.update_account(
        patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}]
    )
    cleared = apigw.get_account()
    assert cleared.get("cloudwatchRoleArn", "") == "", (
        f"positive control: expected cloudwatchRoleArn cleared via replace with '', got "
        f"{cleared.get('cloudwatchRoleArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
