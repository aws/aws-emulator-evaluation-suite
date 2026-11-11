"""send-agreement-payment-request-name-too-short-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-agreement-payment-request-name-too-short-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendAgreementPaymentRequest sent past client-side validation refuses a name under 5 characters with
    ValidationException "Provided name is invalid.", while a valid name gets the agreement id refusal.
    """
    # marketplace-agreement answers only in us-east-1, so both clients pin that region.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    unvalidated = ctx.client(
        "marketplace-agreement", region="us-east-1", config=Config(parameter_validation=False)
    )
    fake_agreement_id = ctx.unique_name("sim2real-no-such-agreement-")

    bad_code, bad_message = _error_code(
        lambda: unvalidated.send_agreement_payment_request(
            agreementId=fake_agreement_id,
            termId="sim2real-term",
            name="hi",
            chargeAmount="1.00",
        )
    )
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_message == "Provided name is invalid.", f"unexpected message: {bad_message!r}"

    # Control: a name that satisfies the length constraint clears field validation. Real AWS
    # answers a missing/invalid agreement or termId with ValidationException too (not
    # ResourceNotFoundException), so the proof that the `name` length triggered the bad case is
    # that the control's rejection names the agreement id instead.
    control_code, control_message = _error_code(
        lambda: mpa.send_agreement_payment_request(
            agreementId=fake_agreement_id,
            termId="sim2real-term",
            name="a valid payment request name",
            chargeAmount="1.00",
        )
    )
    assert control_code == "ValidationException", f"expected ValidationException, got {control_code!r}"
    assert control_message == "Provided agreement id is invalid.", (
        f"unexpected message: {control_message!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
