"""send-to-unverified-recipient-refused-both-apis-then-simulator-accepted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "send-to-unverified-recipient-refused-both-apis-then-simulator-accepted"
GROUP = "overly-permissive"
SERVICES = ["ses", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_SIMULATOR_TO = "success@simulator.amazonses.com"



def _dns_baseline_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _refusal(send):
    """The Error dict ``send`` raises; an unexpected success raises too."""
    try:
        result = send()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"SendEmail to an unverified, non-simulator recipient must be refused; got {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """In the SES sandbox, SendEmail from a verified sender to a recipient that is neither
    verified nor the mailbox simulator is refused by both APIs with MessageRejected naming that
    recipient; the same sender reaches the simulator successfully.
    """
    route53 = ctx.client("route53")
    v2 = ctx.client("sesv2")
    v1 = ctx.client("ses")

    domain = _dns_baseline_domain(ctx, route53, v2)
    sender = f"{ctx.unique_name('sender-')}@{domain}"
    # A reserved test domain no account can verify: the address is refused, never mailed.
    recipient = f"{ctx.unique_name('recipient-')}@recipient.test"
    expected_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {recipient}"
    )

    err_v2 = _refusal(
        lambda: v2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [recipient]},
            Content={"Simple": {
                "Subject": {"Data": "Recipient check"},
                "Body": {"Text": {"Data": "this send must be refused"}},
            }},
        )
    )
    assert err_v2.get("Code") == "MessageRejected", f"sesv2 SendEmail: expected MessageRejected, got {err_v2!r}"
    assert err_v2.get("Message") == expected_msg, (
        f"MessageRejected must name the recipient that failed the verification check; "
        f"expected {expected_msg!r}, got {err_v2.get('Message')!r}"
    )

    err_v1 = _refusal(
        lambda: v1.send_email(
            Source=sender,
            Destination={"ToAddresses": [recipient]},
            Message={
                "Subject": {"Data": "Recipient check"},
                "Body": {"Text": {"Data": "this send must be refused"}},
            },
        )
    )
    assert err_v1.get("Code") == "MessageRejected", f"v1 SendEmail: expected MessageRejected, got {err_v1!r}"
    assert err_v1.get("Message") == expected_msg, (
        f"v1 SendEmail must refuse with the same message as v2; expected {expected_msg!r}, "
        f"got {err_v1.get('Message')!r}"
    )

    # Positive control: the same sender reaches the one recipient the sandbox always accepts.
    accepted = v2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [_SIMULATOR_TO]},
        Content={"Simple": {
            "Subject": {"Data": "Recipient check control"},
            "Body": {"Text": {"Data": "this send must succeed"}},
        }},
    )
    message_id = accepted["MessageId"]
    assert isinstance(message_id, str) and len(message_id) > 0, (
        f"expected a non-empty string MessageId sending to the mailbox simulator, got {message_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
