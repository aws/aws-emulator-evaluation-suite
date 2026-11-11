"""delete-resource-policy-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-access-denied"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy by a principal under an explicit IAM Deny returns AccessDeniedException,
    while the identical call on the same guardrail by the full-permission owner succeeds (the delete
    is idempotent), so the refusal is the permission check and not the resource.
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    bedrock = ctx.client("bedrock")

    account_id = sts.get_caller_identity()["Account"]

    guardrail_name = ctx.unique_name("sim2real-behav-gr-")
    guardrail = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"managedWordListsConfig": [{"type": "PROFANITY"}]},
    )
    guardrail_arn = guardrail["guardrailArn"]
    ctx.on_cleanup(
        lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail["guardrailId"])
    )

    role_name = ctx.unique_name("sim2real-bedrock-norights-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # No permissions policy attached; also attach an *explicit* Deny on every
    # action so the check is deterministic even if this account has some unusual
    # default-allow baseline -- an explicit Deny always wins over any Allow.
    deny_policy_name = ctx.unique_name("sim2real-deny-bedrock-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    )
    # Verify the policy really landed on the role before trusting any subsequent
    # "success" as meaningful (a get here also gives IAM a moment to converge).
    attached = iam.get_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    assert attached["PolicyName"] == deny_policy_name

    restricted_bedrock = _assume_role_client(ctx, sts, role_arn, "bedrock")
    restricted_sts = _assume_role_client(ctx, sts, role_arn, "sts")
    restricted_identity = restricted_sts.get_caller_identity()

    # Sanity control: an unrelated write call (CreateGuardrail) must also be denied
    # for this same principal under the blanket Deny. A freshly attached inline
    # policy is eventually consistent -- poll (bounded) rather than judging on the
    # first attempt, since a stray premature success just means the Deny hasn't
    # propagated to this call path yet. If it never propagates within the window,
    # IAM restriction is demonstrably not being enforced/observable for this
    # principal in this account, so the AccessDeniedException half of this check
    # cannot be exercised here at all.
    sanity_deadline = time.monotonic() + 60.0
    sanity_code = sanity_message = None
    while True:
        try:
            sanity_created = restricted_bedrock.create_guardrail(
                name=ctx.unique_name("sim2real-behav-gr-sanity-"),
                blockedInputMessaging="x",
                blockedOutputsMessaging="x",
                wordPolicyConfig={"managedWordListsConfig": [{"type": "PROFANITY"}]},
            )
        except ClientError as exc:
            sanity_code = exc.response["Error"]["Code"]
            sanity_message = exc.response["Error"].get("Message")
            break
        else:
            sanity_id = sanity_created["guardrailId"]
            ctx.on_cleanup(
                lambda sanity_id=sanity_id: bedrock.delete_guardrail(guardrailIdentifier=sanity_id)
            )
            if time.monotonic() >= sanity_deadline:
                break
            time.sleep(3.0)
    if sanity_code != "AccessDeniedException":
        raise AssertionError(
            "a principal with an explicit blanket Deny (Action=*, Resource=*) "
            f"still succeeded calling CreateGuardrail (identity "
            f"{restricted_identity.get('Arn')!r}) even after waiting for IAM "
            "policy propagation; IAM identity-based restriction is not "
            "observably enforced for Bedrock control-plane calls in this "
            "account, so the AccessDeniedException half of this check cannot be "
            "exercised here"
        )
    expected_sanity = (
        f"User: {restricted_identity['Arn']} is not authorized to perform: bedrock:CreateGuardrail "
        f"on resource: arn:aws:bedrock:{ctx.region}:{restricted_identity['Account']}:guardrail/* "
        "with an explicit deny in an identity-based policy"
    )
    assert sanity_message == expected_sanity, f"expected {expected_sanity!r}, got {sanity_message!r}"

    # IAM policy attachment is eventually consistent -- poll until the explicit
    # Deny is actually enforced (bounded; a stray premature success just means the
    # policy hasn't propagated to this call path yet).
    deadline = time.monotonic() + 60.0
    while True:
        code, message = _outcome(
            lambda: restricted_bedrock.delete_resource_policy(resourceArn=guardrail_arn)
        )
        if code == "AccessDeniedException" or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert code == "AccessDeniedException", (
        f"got {code!r}; restricted caller identity was {restricted_identity.get('Arn')!r}"
    )
    expected_denial = (
        f"User: {restricted_identity['Arn']} is not authorized to perform: "
        f"bedrock:DeleteResourcePolicy on resource: {guardrail_arn} with an explicit deny in an "
        "identity-based policy"
    )
    assert message == expected_denial, f"expected {expected_denial!r}, got {message!r}"

    # Positive control: the same call with full permissions is not blocked by IAM at all -- it
    # succeeds. DeleteResourcePolicy is idempotent on a guardrail with no policy attached
    # (it does NOT raise ResourceNotFoundException).
    bedrock.delete_resource_policy(resourceArn=guardrail_arn)

    # ...and the guardrail itself is still there, so the control call reached the real resource
    # rather than being short-circuited.
    still_there = bedrock.get_guardrail(guardrailIdentifier=guardrail["guardrailId"])
    assert still_there["guardrailId"] == guardrail["guardrailId"], still_there


# ===== helpers =====
def _outcome(fn):
    """Call fn(); return the refusal's (code, message), or ("<succeeded>", None) on success, which
    the caller's poll retries until the Deny propagates."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "<succeeded>", None


def _assume_role_client(ctx, sts, role_arn: str, service: str, timeout_s: float = 60.0):
    # ctx.client's creds override signs as the restricted principal against the same target.
    # A freshly created role is not always immediately assumable (IAM eventual
    # consistency); poll on the AssumeRole call itself.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behavioral-check"
            )["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"could not assume role {role_arn!r} in time: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

