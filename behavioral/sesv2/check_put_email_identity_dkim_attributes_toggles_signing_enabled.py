"""put-email-identity-dkim-attributes-toggles-signing-enabled."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-email-identity-dkim-attributes-toggles-signing-enabled"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEmailIdentityDkimAttributes(SigningEnabled=...) toggles DKIM signing for an identity,
    and each new value is visible through GetEmailIdentity.
    """
    ses = ctx.client("sesv2")
    domain = ctx.unique_name("sim2real-behav-dkimtoggle-") + ".example.com"
    ses.create_email_identity(
        EmailIdentity=domain, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=domain))

    # A freshly created domain identity signs with DKIM by default.
    initial = ses.get_email_identity(EmailIdentity=domain)["DkimAttributes"]
    assert initial["SigningEnabled"] is True, (
        f"expected a freshly created identity to have DKIM SigningEnabled=True, got "
        f"{initial.get('SigningEnabled')!r}"
    )

    ses.put_email_identity_dkim_attributes(EmailIdentity=domain, SigningEnabled=False)
    disabled = ses.get_email_identity(EmailIdentity=domain)["DkimAttributes"]
    assert disabled["SigningEnabled"] is False, (
        f"PutEmailIdentityDkimAttributes(SigningEnabled=False) did not stick: GetEmailIdentity "
        f"reports SigningEnabled={disabled.get('SigningEnabled')!r}"
    )

    ses.put_email_identity_dkim_attributes(EmailIdentity=domain, SigningEnabled=True)
    reenabled = ses.get_email_identity(EmailIdentity=domain)["DkimAttributes"]
    assert reenabled["SigningEnabled"] is True, (
        f"PutEmailIdentityDkimAttributes(SigningEnabled=True) did not stick: GetEmailIdentity "
        f"reports SigningEnabled={reenabled.get('SigningEnabled')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
