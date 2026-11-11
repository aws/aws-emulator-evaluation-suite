"""legacy-verified-email-address-apis."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "legacy-verified-email-address-apis"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _email_identities(ses) -> set[str]:
    """Every email-address identity in the account, paginated: a shared account can push ours
    off page one, which would fake both the presence and the absence reads."""
    found: set[str] = set()
    for page in ses.get_paginator("list_identities").paginate(IdentityType="EmailAddress"):
        found.update(page["Identities"])
    return found


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVerifiedEmailAddresses filters to Success identities, so a Pending identity is absent from it despite showing in ListIdentities.

    VerifyEmailAddress (deprecated) creates the identity in Pending and ListIdentities
    shows it immediately, but ListVerifiedEmailAddresses returns only verified addresses.
    """
    ses = ctx.client("ses")
    email = _unique_email(ctx, "legacy-")
    ses.verify_email_address(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    assert email in _email_identities(ses), (
        "identity missing from ListIdentities after VerifyEmailAddress"
    )
    status = ses.get_identity_verification_attributes(Identities=[email])[
        "VerificationAttributes"
    ][email]["VerificationStatus"]
    assert status == "Pending", f"expected Pending for a freshly verified email, got {status!r}"

    # Pending => NOT in the legacy verified-only listing.
    verified = ses.list_verified_email_addresses()["VerifiedEmailAddresses"]
    assert email not in verified, "pending identity leaked into ListVerifiedEmailAddresses"

    ses.delete_verified_email_address(EmailAddress=email)
    _poll_until(
        lambda: email in _email_identities(ses),
        lambda present: present is False,
        timeout_s=60,
        interval_s=2.0,
        description="identity removed after DeleteVerifiedEmailAddress",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
