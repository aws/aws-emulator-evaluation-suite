"""send-email-verification-code-malformed-email-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-verification-code-malformed-email-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendEmailVerificationCode rejects a malformed email address with ValidationException,
    while the exact same call with a syntactically valid (if undeliverable) address succeeds --
    proving the email format, and only the email format, was rejected."""
    pca = _pca_client(ctx)

    code, message = _error(lambda: pca.send_email_verification_code(Catalog="AWS", Email="not-an-email-address"))
    assert code == "ValidationException", f"expected ValidationException for malformed email, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not-an-email-address' at 'email' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    ), message

    valid_email = f"sim2real-{uuid.uuid4().hex[:8]}@example.com"
    # Positive control: the identical call with a syntactically valid address must succeed,
    # proving the rejection above was specific to the email format and not a blanket refusal.
    pca.send_email_verification_code(Catalog="AWS", Email=valid_email)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
