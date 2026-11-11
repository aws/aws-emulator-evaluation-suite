"""check-phone-number-opted-out-invalid-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-phone-number-opted-out-invalid-fails"
GROUP = 'validation'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of its ClientError.

    An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckIfPhoneNumberIsOptedOut rejects a malformed phone number with InvalidParameter and
    the exact message, while a well-formed number returns isOptedOut (positive control)."""
    sns = ctx.client("sns")
    suffix = uuid.uuid4().int % 10000
    control_number = f"+1500555{suffix:04d}"

    resp = sns.check_if_phone_number_is_opted_out(phoneNumber=control_number)
    assert "isOptedOut" in resp, f"positive control did not return isOptedOut: {resp}"

    code, message = _error(
        lambda: sns.check_if_phone_number_is_opted_out(phoneNumber="not-a-phone")
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == "Invalid parameter: PhoneNumber Reason: input incorrectly formatted", (
        f"unexpected InvalidParameter message for a malformed phone number: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
