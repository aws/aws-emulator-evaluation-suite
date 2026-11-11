"""authorization-error-explicit-deny-returns-correct-code."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "authorization-error-explicit-deny-returns-correct-code"
GROUP = "error-semantics"
SERVICES = ["sns"]

_POLICY = "sns-sandbox-status-allow-and-deny"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny beside an explicit Allow refuses sns:GetSMSSandboxAccountStatus with
    AuthorizationErrorException and the exact message, while the same user's allowed
    sts:GetCallerIdentity and the caller's identical SNS call succeed."""
    iam = ctx.client("iam")
    sns_admin = ctx.client("sns")

    user_name = ctx.unique_name("sim2real-behav-sns-deny-")

    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.put_user_policy(
        UserName=user_name,
        PolicyName=_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
                {"Effect": "Allow", "Action": "sns:GetSMSSandboxAccountStatus", "Resource": "*"},
                {"Effect": "Deny", "Action": "sns:GetSMSSandboxAccountStatus", "Resource": "*"},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=_POLICY))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    user_creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    as_user_sns = ctx.client("sns", creds=user_creds)
    as_user_sts = ctx.client("sts", creds=user_creds)

    # A new access key takes time to propagate; this rules out an unpropagated key below.
    live = _poll(
        lambda: _probe(as_user_sts, "get_caller_identity"),
        lambda r: r[0] == "UNEXPECTED_SUCCESS",
        timeout_s=90.0,
        interval_s=2.0,
        description="the new key/policy becomes live for sts:GetCallerIdentity",
    )
    assert live[0] == "UNEXPECTED_SUCCESS", (
        f"the identity's own Allow for sts:GetCallerIdentity must succeed once the key "
        f"propagates, or nothing below is interpretable; got {live[0]!r}"
    )

    # The refusal names the caller and the account-wide SNS resource of the region.
    partition, account = user_arn.split(":")[1], user_arn.split(":")[4]
    expected_message = (
        f"User: {user_arn} is not authorized to perform: SNS:GetSMSSandboxAccountStatus "
        f"on resource: arn:{partition}:sns:{ctx.region}:{account}:* "
        f"with an explicit deny in an identity-based policy"
    )

    # Sampled repeatedly so a single transient reading is not taken as the steady state.
    for _ in range(3):
        denied = _poll(
            lambda: _probe(as_user_sns, "get_sms_sandbox_account_status"),
            lambda r: r[0] != "UNEXPECTED_SUCCESS",
            timeout_s=60.0,
            interval_s=2.0,
            description="the explicit Deny (despite the sibling Allow) refuses the real signed call",
        )
        assert denied[0] == "AuthorizationError", (
            f"a policy carrying both an explicit Allow and an explicit Deny for "
            f"sns:GetSMSSandboxAccountStatus must refuse the real signed call with exactly "
            f"AuthorizationErrorException, never a generic 403 or InternalErrorException; got "
            f"{denied[0]!r}"
        )
        assert denied[2] == expected_message, (
            f"unexpected AuthorizationError message for the explicit Deny: {denied[2]!r}"
        )
        admin_resp = sns_admin.get_sms_sandbox_account_status()
        assert isinstance(admin_resp["IsInSandbox"], bool), (
            f"the unrestricted identity's identical call must keep succeeding with a boolean "
            f"IsInSandbox at the same moment the restricted identity is refused; got "
            f"{admin_resp!r}"
        )


def _probe(client, op_name):
    from botocore.exceptions import ClientError

    try:
        resp = getattr(client, op_name)()
        return "UNEXPECTED_SUCCESS", resp, None
    except ClientError as e:
        return e.response["Error"]["Code"], None, e.response["Error"].get("Message")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
