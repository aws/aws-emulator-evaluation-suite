"""send-custom-verification-email-sandbox-gate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-custom-verification-email-sandbox-gate"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises.

    An unexpected success raises, so a target that accepts what AWS refuses fails loudly
    instead of reading as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendCustomVerificationEmail from a sandbox account with an absent template is refused with
    ProductionAccessNotGranted and its exact message (the sandbox gate comes before the template
    lookup), and the target address does not become an identity."""
    ses = ctx.client("ses")
    target = _unique_email(ctx, "cvt-target-")
    err = _err(
        lambda: ses.send_custom_verification_email(
            EmailAddress=target,
            TemplateName=ctx.unique_name("sim2real-behav-cvt-absent-"),
        )
    )
    assert err == (
        "ProductionAccessNotGranted",
        "Production access not granted. Please request production access prior to sending "
        "custom verification emails",
    ), (
        f"expected ProductionAccessNotGranted (sandbox gate before template lookup), got {err!r}"
    )

    # The target address must not have been created as an identity.
    assert target not in ses.list_identities(IdentityType="EmailAddress")["Identities"], (
        "SendCustomVerificationEmail must not create the target identity when gated"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
