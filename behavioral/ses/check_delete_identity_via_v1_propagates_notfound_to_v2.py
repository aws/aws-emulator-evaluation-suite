"""delete-identity-via-v1-propagates-notfound-to-v2."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-via-v1-propagates-notfound-to-v2"
GROUP = "identity-v2"
SERVICES = ["ses"]


_POLL_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 2.0


def _unique_email(ctx, prefix: str) -> str:
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _poll(fn, what: str):
    """Poll ``fn()`` every 2 s until it returns a truthy value; raise at the deadline."""
    deadline = time.monotonic() + _POLL_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(f"{what} not reached within {_POLL_TIMEOUT_S}s; last observation {last!r}")


def _v2_status(v2, identity: str):
    """The v2 VerificationStatus of ``identity``, or None while v2 reports it NotFound."""
    try:
        return v2.get_email_identity(EmailIdentity=identity)["VerificationStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _v2_refusal(v2, identity: str) -> tuple[str, str]:
    """The ``(code, message)`` v2 GetEmailIdentity refuses ``identity`` with; a success raises."""
    try:
        found = v2.get_email_identity(EmailIdentity=identity)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"v2 GetEmailIdentity still returns {identity!r}: {found!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentity through v1 removes the identity from the shared store: v2 GetEmailIdentity
    then raises NotFoundException and v1 GetIdentityVerificationAttributes no longer names it.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    deleted = _unique_email(ctx, "v1del-")
    v1.verify_email_identity(EmailAddress=deleted)
    ctx.on_cleanup(lambda _e=deleted: v1.delete_identity(Identity=_e))

    control = _unique_email(ctx, "v1control-")
    v1.verify_email_identity(EmailAddress=control)
    ctx.on_cleanup(lambda _e=control: v1.delete_identity(Identity=_e))

    status = _poll(lambda: _v2_status(v2, deleted), f"v2 visibility of {deleted!r}")
    assert status == "PENDING", (
        f"setup precondition: the identity must be PENDING through v2 before it is deleted, got "
        f"{status!r}"
    )

    v1.delete_identity(Identity=deleted)

    _poll(lambda: _v2_status(v2, deleted) is None, f"v2 NotFound for {deleted!r}")
    code, message = _v2_refusal(v2, deleted)
    assert code == "NotFoundException", (
        f"expected NotFoundException reading the v1-deleted identity {deleted!r}, got "
        f"{code!r}: {message!r}"
    )
    assert message == f"Email identity <{deleted}> does not exist.", (
        f"the NotFoundException must name the deleted identity {deleted!r}, got {message!r}"
    )

    _poll(
        lambda: deleted not in v1.get_identity_verification_attributes(Identities=[deleted])[
            "VerificationAttributes"
        ],
        f"v1 GetIdentityVerificationAttributes dropping {deleted!r}",
    )

    status = _poll(lambda: _v2_status(v2, control), f"v2 visibility of {control!r}")
    assert status == "PENDING", (
        f"control: deleting one identity must not remove the other, got status {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
