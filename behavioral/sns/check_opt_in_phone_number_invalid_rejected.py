"""opt-in-phone-number-invalid-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "opt-in-phone-number-invalid-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OptInPhoneNumber must reject a phone number that is not in E.164 format."""
    sns = ctx.client("sns")

    suffix = uuid.uuid4().int % 10000
    valid_number = f"+1500555{suffix:04d}"
    sns.opt_in_phone_number(phoneNumber=valid_number)
    resp = sns.check_if_phone_number_is_opted_out(phoneNumber=valid_number)
    assert resp["isOptedOut"] is False, (
        f"OptInPhoneNumber on a valid number must leave it opted in, got {resp}"
    )

    code, message = _error(lambda: sns.opt_in_phone_number(phoneNumber="not-a-phone-number"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a malformed phone number, got {code}"
    )
    expected = 'Invalid parameter: PhoneNumber Reason: input incorrectly formatted'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    opted_out = set()
    for page in sns.get_paginator("list_phone_numbers_opted_out").paginate():
        opted_out.update(page.get("phoneNumbers", []))
    assert "not-a-phone-number" not in opted_out, (
        f"rejected malformed number must not appear in opt-out state: {opted_out}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
