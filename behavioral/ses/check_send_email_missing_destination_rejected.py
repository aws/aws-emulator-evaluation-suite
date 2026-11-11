"""send-email-missing-destination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-missing-destination-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected SendEmail to be rejected for an empty Destination, but it SUCCEEDED "
        f"and returned {result!r}"
    )


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail with an empty Destination fails structural validation (ValidationError) BEFORE the identity gate.

    Structural request validation runs before the sandbox/identity check, so the code
    is ValidationError, not the MessageRejected an unverified source would produce.
    """
    ses = ctx.client("ses")
    sender = _unique_email(ctx, "nodest-")
    ses.verify_email_identity(EmailAddress=sender)
    ctx.on_cleanup(lambda _n=sender: ses.delete_identity(Identity=_n))

    err = _err(
        lambda: ses.send_email(
            Source=sender,
            Destination={},
            Message={"Subject": {"Data": "hi"}, "Body": {"Text": {"Data": "body"}}},
        )
    )
    assert err == (
        "ValidationError",
        "1 validation error detected: Value at 'destination' failed to satisfy constraint: "
        "Member must not be null",
    ), (
        f"expected ValidationError for an empty Destination, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
