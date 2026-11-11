"""partner-app-presigned-url-expires-after-ttl."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partner-app-presigned-url-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartnerApp for an unsubscribed partner type (comet) fails with a Marketplace
    subscription ValidationException and creates no app; without a subscription no app or
    presigned URL can exist, so the URL TTL itself is unreachable."""
    sm = ctx.client("sagemaker")

    # Positive control: SageMaker is otherwise reachable, so the rejection below is the
    # marketplace-entitlement gate, not a broad deny.
    sm.list_partner_apps()

    role_arn = _create_sagemaker_execution_role(ctx)
    app_name = ctx.unique_name("sim2realsmpartner").replace("-", "")

    code, message = _create_partner_app_expect_marketplace_rejection(sm, role_arn, app_name)
    assert code == "ValidationException", (
        f"expected ValidationException for an unsubscribed Partner AI App type, got {code!r} ({message!r})"
    )
    expected = "Caller is not subscribed to the marketplace offering."
    assert message == expected, (
        f"expected the marketplace-subscription ValidationException {expected!r}, got: {message!r}"
    )

    # Effect absent: the rejected call created nothing.
    names = {app["Name"] for app in sm.list_partner_apps().get("Summaries", [])}
    assert app_name not in names, f"{app_name} should not exist after a rejected CreatePartnerApp"


def _create_partner_app_expect_marketplace_rejection(sm, role_arn, name, attempts=4, interval_s=5.0):
    last_code, last_message = None, None
    for attempt in range(attempts):
        code, message = _error_code_and_message(
            lambda: sm.create_partner_app(
                Name=name,
                Type="comet",
                Tier="Small",
                AuthType="IAM",
                ExecutionRoleArn=role_arn,
            )
        )
        if code == "ValidationException" and message and "marketplace" in message.lower():
            return code, message
        last_code, last_message = code, message
        if attempt < attempts - 1:
            # Tolerates IAM role/PassRole propagation lag before CreatePartnerApp reaches the
            # marketplace-subscription check; a not-yet-propagated role surfaces a transient
            # role/PassRole error instead.
            time.sleep(interval_s)
    raise AssertionError(
        "CreatePartnerApp never reached the expected marketplace-subscription "
        f"ValidationException after {attempts} attempts (last: {last_code!r} {last_message!r})"
    )


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("CreatePartnerApp unexpectedly succeeded against an unsubscribed account")


def _create_sagemaker_execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    return role["Arn"]


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
