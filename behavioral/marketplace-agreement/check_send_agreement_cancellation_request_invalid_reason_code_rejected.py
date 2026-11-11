"""send-agreement-cancellation-request-invalid-reason-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-agreement-cancellation-request-invalid-reason-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendAgreementCancellationRequest refuses a reasonCode outside the enum with ValidationException
    before checking the agreement, while a valid reasonCode gets ResourceNotFoundException for the same
    fabricated agreement, each with its exact message.
    """
    # marketplace-agreement answers only in us-east-1, so the client pins that region.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    fake_agreement_id = ctx.unique_name("sim2real-no-such-agreement-")

    bad_code, bad_message = _error_code(
        lambda: mpa.send_agreement_cancellation_request(
            agreementId=fake_agreement_id, reasonCode="MADE_UP_REASON"
        )
    )
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_message == "Provided reason code is invalid.", f"unexpected message: {bad_message!r}"

    # Control: a valid reasonCode enum value clears field validation and instead fails because
    # the (fabricated) agreement doesn't exist.
    control_code, control_message = _error_code(
        lambda: mpa.send_agreement_cancellation_request(
            agreementId=fake_agreement_id, reasonCode="OTHER"
        )
    )
    assert control_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {control_code!r}"
    assert control_message == "Provided agreement does not exist.", (
        f"unexpected message: {control_message!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
