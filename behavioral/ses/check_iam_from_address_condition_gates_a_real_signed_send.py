"""iam-from-address-condition-gates-a-real-signed-send."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-from-address-condition-gates-a-real-signed-send"
GROUP = "sending"
SERVICES = ["ses"]

_POLICY_NAME = "sim2real-behav-ses-fromaddress-condition"


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _unverified_msg(region: str, identity: str) -> str:
    """The MessageRejected text SES returns for a From identity that is not verified."""
    return (
        "Email address is not verified. The following identities failed the check in region "
        f"{region.upper()}: {identity}"
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


def _delete_user_verified(iam, user: str) -> None:
    """A long-lived IAM access key is a real credential, so the teardown is verified rather than
    best-effort. ctx.on_cleanup swallows exceptions, so print the leak before raising."""
    try:
        for meta in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=meta["AccessKeyId"])
        for name in iam.list_user_policies(UserName=user)["PolicyNames"]:
            iam.delete_user_policy(UserName=user, PolicyName=name)
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        print(f"LEAK: could not tear down IAM user {user}")
        raise
    try:
        iam.get_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    print(f"LEAK: IAM user {user} still present after delete_user")
    raise AssertionError(f"IAM user {user} still present after delete_user")


def _send_policy(from_addresses: list[str]) -> str:
    """Allow the SES send actions, but ONLY when the request's From address is one of
    ``from_addresses``. https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html
    ("Restricting the 'From' Address")."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ses:SendEmail", "ses:SendRawEmail"],
                    "Resource": "*",
                    "Condition": {"StringEquals": {"ses:FromAddress": from_addresses}},
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A From address outside the caller's `ses:FromAddress` condition gets AccessDenied; a named
    one reaches the identity gate (MessageRejected), widening the policy lets the denied one
    through, and no refused send moves SentLast24Hours or creates an identity.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html
    """
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # RFC 2606 reserved TLD: neither address can reach a real mailbox.
    domain = f"{ctx.unique_name('sim2real-behav-fromcond-')}.example.com"
    allowed = f"allowed@{domain}"
    denied = f"denied@{domain}"

    user = ctx.unique_name("sim2real-behav-ses-fromcond-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_verified(iam, user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    assert user_arn.endswith(f":{account}:user/{user}"), (
        f"the minted principal must be this check's own user in the account "
        f"{account}; GetUser reported {user_arn!r}"
    )

    iam.put_user_policy(
        UserName=user, PolicyName=_POLICY_NAME, PolicyDocument=_send_policy([allowed])
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = ctx.client(
        "ses",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
            "aws_session_token": None,
        },
    )

    def _send_from(source: str) -> dict:
        return _client_error(
            lambda: as_user.send_email(
                Source=source,
                # The mailbox simulator keeps a wrongly accepted send away from real inboxes;
                # `success@` avoids a bounce or complaint against the account's reputation.
                Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
                Message={
                    "Subject": {"Data": "sim2real ses:FromAddress condition probe"},
                    "Body": {"Text": {"Data": "This send must be refused."}},
                },
            )
        )

    quota_before = ses.get_send_quota()["SentLast24Hours"]

    # MessageRejected (not AccessDenied) proves the allowed address passed authorization: the
    # identity gate is downstream of it. The poll covers IAM propagation.
    allowed_err = _poll(
        lambda: _send_from(allowed),
        lambda e: e.get("Code") == "MessageRejected",
        timeout_s=90,
        interval_s=5,
        description="the ses:FromAddress grant becomes effective for the named From address",
    )
    assert allowed_err.get("Code") == "MessageRejected", (
        f"the policy names {allowed!r} in ses:FromAddress, so the signed send must pass "
        f"authorization and be refused only by SES's identity gate with MessageRejected; got "
        f"{allowed_err.get('Code')!r}: {allowed_err.get('Message')!r}"
    )
    expected_allowed_msg = _unverified_msg(ctx.region, allowed)
    assert allowed_err.get("Message") == expected_allowed_msg, (
        f"MessageRejected must name the unverified identity that failed the gate; expected "
        f"{expected_allowed_msg!r}, got {allowed_err.get('Message')!r}"
    )

    # Three reads: a single AccessDenied could be an IAM propagation artifact.
    denied_errs = [_send_from(denied) for _ in range(3)]
    codes = [e.get("Code") for e in denied_errs]
    assert codes == ["AccessDenied", "AccessDenied", "AccessDenied"], (
        f"a From address the caller's ses:FromAddress condition does not name must be refused "
        f"with AccessDenied on every attempt, not once; got {codes!r} "
        f"(last message {denied_errs[-1].get('Message')!r})"
    )
    # The refusal names the denied principal, the action and the From identity's ARN, so it can
    # be told apart from a malformed request or a blanket "no SES permission at all".
    expected_denied_msg = (
        f"User '{user_arn}' is not authorized to perform 'ses:SendEmail' on resource "
        f"'arn:aws:ses:{ctx.region}:{account}:identity/{denied}'"
    )
    denied_msgs = [e.get("Message") for e in denied_errs]
    assert denied_msgs == [expected_denied_msg] * 3, (
        f"expected every AccessDenied to read {expected_denied_msg!r}, got {denied_msgs!r}"
    )

    attrs = ses.get_identity_verification_attributes(Identities=[allowed, denied])[
        "VerificationAttributes"
    ]
    assert allowed not in attrs and denied not in attrs, (
        f"a refused send must not create an identity; GetIdentityVerificationAttributes reported "
        f"{sorted(attrs)!r} for {[allowed, denied]!r}"
    )

    # Widen the condition to name both addresses; nothing else changes.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_POLICY_NAME,
        PolicyDocument=_send_policy([allowed, denied]),
    )
    stored = iam.get_user_policy(UserName=user, PolicyName=_POLICY_NAME)["PolicyDocument"]
    # botocore's IAM handler URL-decodes and JSON-parses policy documents, so this is normally a
    # dict; a target that returns the raw string is parsed here rather than crashing the read.
    document = stored if isinstance(stored, dict) else json.loads(stored)
    condition_values = document["Statement"][0]["Condition"]["StringEquals"]["ses:FromAddress"]
    assert sorted(condition_values) == sorted([allowed, denied]), (
        f"the widened policy must be observably stored before anything is concluded from its "
        f"effect; GetUserPolicy reported ses:FromAddress={condition_values!r}"
    )

    widened = _poll(
        lambda: _send_from(denied),
        lambda e: e.get("Code") == "MessageRejected",
        timeout_s=90,
        interval_s=5,
        description="widening ses:FromAddress lets the previously denied From address through "
        "authorization",
    )
    assert widened.get("Code") == "MessageRejected", (
        f"once the condition names {denied!r} the identical signed send must pass authorization "
        f"and be refused only by the identity gate; got {widened.get('Code')!r}: "
        f"{widened.get('Message')!r}"
    )
    expected_widened_msg = _unverified_msg(ctx.region, denied)
    assert widened.get("Message") == expected_widened_msg, (
        f"expected the post-widening MessageRejected to read {expected_widened_msg!r}, got "
        f"{widened.get('Message')!r}"
    )

    quota_after = ses.get_send_quota()["SentLast24Hours"]
    assert quota_after - quota_before < 1.0, (
        f"none of the refused sends may be counted: GetSendQuota.SentLast24Hours moved "
        f"{quota_before} -> {quota_after}"
    )
    listed = set(ses.list_identities(MaxItems=1000)["Identities"])
    assert not listed & {allowed, denied, domain}, (
        f"a refused send must leave no identity behind; ListIdentities contains "
        f"{sorted(listed & {allowed, denied, domain})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
