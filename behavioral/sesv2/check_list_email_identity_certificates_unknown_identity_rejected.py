"""list-email-identity-certificates-unknown-identity-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-email-identity-certificates-unknown-identity-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEmailIdentityCertificates for a non-existent identity raises NotFoundException."""
    ses = ctx.client("sesv2")

    existing_identity = ctx.unique_name("sim2real-listcert-") + "@example.com"
    ses.create_email_identity(
        EmailIdentity=existing_identity, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=existing_identity))

    missing_identity = ctx.unique_name("sim2real-nolistcert-") + "@example.com"

    missing_message = f"Email identity <{missing_identity}> does not exist."
    err = _error(lambda: ses.list_email_identity_certificates(EmailIdentity=missing_identity))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err!r}"
    assert err.get("Message") == missing_message, (
        f"expected message {missing_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: GetEmailIdentity confirms the identity genuinely doesn't exist (the
    # NotFoundException wasn't a bug that also swallowed a real identity).
    get_err = _error(lambda: ses.get_email_identity(EmailIdentity=missing_identity))
    assert get_err.get("Code") == "NotFoundException", f"expected NotFoundException, got {get_err!r}"
    assert get_err.get("Message") == missing_message, (
        f"expected message {missing_message!r}, got {get_err.get('Message')!r}"
    )

    # Positive control: the exact same call against a real identity succeeds.
    resp = ses.list_email_identity_certificates(EmailIdentity=existing_identity)
    assert resp["Certificates"] == [], f"expected no certificates, got {resp['Certificates']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
