"""create-email-identity-leading-hyphen-domain-label-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-identity-leading-hyphen-domain-label-rejected"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Calls ``fn``, asserting it raises exactly ``code``/``message``; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected error code {code!r}, got {err['Code']!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEmailIdentity refuses a domain whose leftmost label starts with a hyphen,
    while the same domain stripped of that character is created and readable.
    """
    ses = ctx.client("sesv2")
    label = ctx.unique_name("sim2real-behav-sesv2hyphen-")
    bad_domain = f"-{label}.example.com"
    good_domain = f"{label}.example.com"

    _CREATE_REFUSED = (
        "BadRequestException",
        f"Identity {bad_domain} is invalid. Must be a valid email address or domain.",
    )
    expect_error(lambda: ses.create_email_identity(EmailIdentity=bad_domain), *_CREATE_REFUSED)

    ses.create_email_identity(
        EmailIdentity=good_domain, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(
        _teardown(lambda: ses.delete_email_identity(EmailIdentity=good_domain), "NotFoundException")
    )

    got = ses.get_email_identity(EmailIdentity=good_domain)
    assert got["IdentityType"] == "DOMAIN", (
        f"expected the valid-syntax domain to be a DOMAIN identity, got {got['IdentityType']!r}"
    )

    _GET_REFUSED = (
        "BadRequestException",
        f"Email identity <{bad_domain}> is invalid.",
    )
    expect_error(lambda: ses.get_email_identity(EmailIdentity=bad_domain), *_GET_REFUSED)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
