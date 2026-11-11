"""accept-agreement-request-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accept-agreement-request-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptAgreementRequest on a well-formed nonexistent agreementRequestId gets
    ResourceNotFoundException, while a malformed id gets ValidationException, each with its exact message.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    got = _error_code(
        lambda: mpa.accept_agreement_request(agreementRequestId="ar-sim2realnonexistentrequest")
    )
    want = ("ResourceNotFoundException", "Provided agreement request does not exist.")
    assert got == want, f"expected {want!r}, got {got!r}"

    # Control: an id that violates the `ar-*` pattern is a *different*, more basic error.
    malformed = _error_code(
        lambda: mpa.accept_agreement_request(agreementRequestId="not-the-right-shape")
    )
    want = ("ValidationException", "Provided agreement request id is invalid.")
    assert malformed == want, f"expected {want!r}, got {malformed!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
