"""email-identity-verification-info-separates-a-missing-dns-zone-from-a-pending-one."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "email-identity-verification-info-separates-a-missing-dns-zone-from-a-pending-one"
GROUP = "identity-v2"
SERVICES = ["sesv2"]

#: RFC 2606 reserves `.invalid` and guarantees it is absent from the DNS root, so no SOA exists at
#: any level above the name. This is a protocol guarantee, not an assumption about a third party.
_NO_ZONE_TLD = "invalid"
#: RFC 2606 reserves `example.com` for documentation AND it is a real, resolvable zone, so a DKIM
#: CNAME lookup under it resolves the hostname but finds no such record (TYPE_NOT_FOUND) rather than
#: finding no hostname at all (HOST_NOT_FOUND).
_ZONE_DOMAIN = "example.com"
#: SES performs the first DNS lookup for a new domain identity asynchronously, and VerificationInfo
#: is only populated once it has.
_VERIFY_DEADLINE_S = 240.0
_VERIFY_INTERVAL_S = 2.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A domain under a TLD absent from DNS reports VerificationInfo ErrorType HOST_NOT_FOUND; one
    under a resolvable zone without the DKIM CNAME reports TYPE_NOT_FOUND; both timestamps are live.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_VerificationInfo.html
    """
    sesv2 = ctx.client("sesv2")
    created_at = time.time()

    no_zone = ctx.unique_name("sim2real-behav-nozone-") + "." + _NO_ZONE_TLD
    with_zone = ctx.unique_name("sim2real-behav-zone-") + "." + _ZONE_DOMAIN
    for domain in (no_zone, with_zone):
        sesv2.create_email_identity(
            EmailIdentity=domain,
            Tags=[
                {"Key": "sim2real-managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": CHECK},
            ],
        )
        ctx.on_cleanup(lambda d=domain: sesv2.delete_email_identity(EmailIdentity=d))

    for domain in (no_zone, with_zone):
        described = sesv2.get_email_identity(EmailIdentity=domain)
        assert described["IdentityType"] == "DOMAIN", (
            f"{domain} was created as a domain but GetEmailIdentity reports "
            f"IdentityType={described['IdentityType']!r}"
        )
        assert described["VerifiedForSendingStatus"] is False, (
            f"{domain} has no DKIM records published anywhere, so VerifiedForSendingStatus must be "
            f"False, got {described['VerifiedForSendingStatus']!r}"
        )

    no_zone_info = _await_verification_info(
        sesv2, no_zone, lambda info: "ErrorType" in info, "an ErrorType"
    )
    assert no_zone_info["ErrorType"] == "HOST_NOT_FOUND", (
        f"{no_zone} sits under the RFC 2606 reserved .{_NO_ZONE_TLD} TLD, which is absent from the "
        f"DNS root, so VerificationInfo.ErrorType must be HOST_NOT_FOUND; got "
        f"{no_zone_info['ErrorType']!r} (full VerificationInfo={no_zone_info!r})"
    )
    no_zone_status = sesv2.get_email_identity(EmailIdentity=no_zone)["VerificationStatus"]
    assert no_zone_status != "SUCCESS", (
        f"{no_zone} cannot resolve in DNS at all, yet VerificationStatus is {no_zone_status!r}"
    )

    # A real zone exists above this name, so the DKIM CNAME lookup fails on record type, not host;
    # VerificationInfo carries no SOARecord here.
    with_zone_info = _await_verification_info(
        sesv2, with_zone, lambda info: "ErrorType" in info, "an ErrorType"
    )
    assert with_zone_info["ErrorType"] == "TYPE_NOT_FOUND", (
        f"{with_zone} sits under the resolvable zone {_ZONE_DOMAIN} (real SOA, real DNS), so the "
        f"DKIM CNAME lookup must fail with TYPE_NOT_FOUND (hostname exists, requested record type "
        f"absent) and nothing else; got {with_zone_info['ErrorType']!r} (full VerificationInfo="
        f"{with_zone_info!r}). Its twin {no_zone} reported HOST_NOT_FOUND at the same moment, so "
        f"the target must distinguish the two, not collapse them."
    )

    # SES cannot have checked either name before this run created it.
    for domain, info in ((no_zone, no_zone_info), (with_zone, with_zone_info)):
        assert "LastCheckedTimestamp" in info, (
            f"{domain}: VerificationInfo carries no LastCheckedTimestamp, so no verification "
            f"attempt is being recorded: {info!r}"
        )
        checked = info["LastCheckedTimestamp"].timestamp()
        assert checked >= created_at - 60.0, (
            f"{domain}: VerificationInfo.LastCheckedTimestamp is {info['LastCheckedTimestamp']} "
            f"({checked}), which predates the moment this run created the identity ({created_at}) "
            f"by more than the 60s clock-skew allowance — the timestamp is not live"
        )


def _await_verification_info(sesv2, domain: str, predicate, wanted: str) -> dict:
    """Poll GetEmailIdentity until VerificationInfo satisfies `predicate`; raise on timeout."""
    deadline = time.monotonic() + _VERIFY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        described = sesv2.get_email_identity(EmailIdentity=domain)
        last = described.get("VerificationInfo")
        if last is not None and predicate(last):
            return last
        time.sleep(_VERIFY_INTERVAL_S)
    raise AssertionError(
        f"GetEmailIdentity({domain}) never reported VerificationInfo carrying {wanted} within "
        f"{_VERIFY_DEADLINE_S}s (last VerificationInfo={last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
