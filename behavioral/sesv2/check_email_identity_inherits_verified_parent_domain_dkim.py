"""email-identity-inherits-verified-parent-domain-dkim."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "email-identity-inherits-verified-parent-domain-dkim"
GROUP = "identity"
SERVICES = ["sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}



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
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )




@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """An email-address identity under a verified parent domain mirrors the parent's DKIM
    SigningEnabled, Status and Tokens instead of getting a fresh pending set of its own.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    domain_dkim = sesv2.get_email_identity(EmailIdentity=domain)["DkimAttributes"]
    assert domain_dkim["Status"] == "SUCCESS", (
        f"precondition: the baseline domain {domain!r} must be DKIM SUCCESS before this check "
        f"can exercise inheritance; got {domain_dkim['Status']!r}"
    )

    child = f"{ctx.unique_name('sim2real-behav-')}@{domain}"
    sesv2.create_email_identity(EmailIdentity=child, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sesv2.delete_email_identity(EmailIdentity=child))

    child_dkim = sesv2.get_email_identity(EmailIdentity=child)["DkimAttributes"]
    assert child_dkim["SigningEnabled"] is True, (
        f"a child identity under a verified domain must inherit SigningEnabled=True; got "
        f"{child_dkim['SigningEnabled']!r}"
    )
    assert child_dkim["Status"] == "SUCCESS", (
        f"a child identity under a verified (DKIM SUCCESS) domain must itself read SUCCESS, "
        f"not a fresh PENDING state of its own; got {child_dkim['Status']!r}"
    )
    assert child_dkim["Tokens"] == domain_dkim["Tokens"], (
        f"the child must carry the SAME DKIM tokens as its parent domain, not a tokenset of its "
        f"own: child={child_dkim['Tokens']!r} parent={domain_dkim['Tokens']!r}"
    )

    # Independent re-read: the mirroring is not a one-time snapshot taken at create time.
    reread = sesv2.get_email_identity(EmailIdentity=child)["DkimAttributes"]
    assert reread["Status"] == "SUCCESS" and reread["Tokens"] == domain_dkim["Tokens"], (
        f"a later GetEmailIdentity on the child must still mirror the parent; got {reread!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
