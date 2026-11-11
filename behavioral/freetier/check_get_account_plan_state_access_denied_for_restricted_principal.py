"""get-account-plan-state-access-denied-for-restricted-principal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-plan-state-access-denied-for-restricted-principal"
GROUP = "overly-permissive"
SERVICES = ["freetier"]

# A freshly minted access key is not recognized everywhere at once; these codes mean "not
# propagated yet", not "denied", and must never be latched onto as the answer under test.
_CREDENTIAL_PROPAGATION_ERRORS = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new IAM user with no policies gets AccessDeniedException and IAM's exact implicit-deny message on
    GetAccountPlanState; after an Allow is added, the same call succeeds or fails with "Missing data for account:
    <id>"."""
    iam = ctx.client("iam")
    freetier = ctx.client("freetier")

    # Positive control: the ambient (already-privileged) caller's own connection is healthy for
    # this API before anything about the new, unprivileged principal is exercised -- otherwise a
    # denial below could mean "freetier is unreachable here" rather than "this principal is denied".
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    control_outcome = "UNEXPECTED_SUCCESS"
    try:
        control = freetier.get_account_plan_state()
        assert control["accountPlanType"] in ("FREE", "PAID"), (
            f"positive control: expected accountPlanType in ('FREE', 'PAID'), "
            f"got {control['accountPlanType']!r}"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"positive control: expected success or ResourceNotFoundException "
            f"(no plan record for this account), got {code!r}"
        )
        message = err.response["Error"].get("Message")
        assert message == f"Missing data for account: {account_id}", (
            f"positive control: expected FreeTier's exact no-plan-record message, got {message!r}"
        )
        control_outcome = code

    user_name = ctx.unique_name("sim2real-behav-freetier-deny-")
    user_arn = iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # The user has no policy, so IAM's default decision is an implicit deny. A new access key propagates
    # gradually: poll past the propagation errors to the credential's settled answer.
    denied, denied_message = _poll(
        lambda: _error(lambda: as_user.get_account_plan_state()),
        lambda e: e[0] not in _CREDENTIAL_PROPAGATION_ERRORS,
        timeout_s=90,
        interval_s=3,
        description="the new access key propagates far enough to get a settled authorization "
        "answer for GetAccountPlanState",
    )
    assert denied == "AccessDeniedException", (
        f"a brand-new IAM user with no policy attached must get the default implicit deny "
        f"(AccessDeniedException) on a real signed call to freetier:GetAccountPlanState; "
        f"got {denied!r}"
    )
    # FreeTier is a global API served from us-east-1, so its resource ARN names that region.
    expected_denial = (
        f"User: {user_arn} is not authorized to perform: freetier:GetAccountPlanState on resource: "
        f"arn:aws:freetier:us-east-1:{account_id}:/GetAccountPlanState because no identity-based "
        f"policy allows the freetier:GetAccountPlanState action"
    )
    assert denied_message == expected_denial, (
        f"expected IAM's exact implicit-deny message {expected_denial!r}; got {denied_message!r}"
    )

    # Restore: an explicit Allow on the same user and connection succeeds (or reaches the documented no-plan
    # error), so the denial came from the empty policy set, not from an unreachable API.
    policy_name = "sim2real-behav-freetier-allow-get-account-plan-state"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "freetier:GetAccountPlanState", "Resource": "*"}
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    restored, restored_message = _poll(
        lambda: _error(lambda: as_user.get_account_plan_state()),
        lambda e: e[0] != "AccessDeniedException",
        timeout_s=90,
        interval_s=3,
        description="granting the Allow policy restores GetAccountPlanState for the same user",
    )
    assert restored != "AccessDeniedException", (
        f"granting an explicit Allow to the same zero-policy user must lift the implicit deny on "
        f"the identical call over the identical connection; got {restored!r}"
    )
    # The account's own plan record decides the answer, so the granted user gets what the
    # privileged caller got above: success, or the no-plan-record error with its exact message.
    assert restored == control_outcome, (
        f"after the Allow grant, the call must answer as the privileged caller's did "
        f"({control_outcome!r}); got {restored!r}: {restored_message!r}"
    )
    if control_outcome == "ResourceNotFoundException":
        assert restored_message == f"Missing data for account: {account_id}", (
            f"expected FreeTier's exact no-plan-record message after the grant, got {restored_message!r}"
        )


def _error(fn):
    """The (code, message) fn() raised, or a code sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "UNEXPECTED_SUCCESS", None


def _client_for_credentials(ctx, access_key_id, secret_access_key):
    """A freetier client signing AS the minted user, not the ambient caller."""
    return ctx.client(
        "freetier",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


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

