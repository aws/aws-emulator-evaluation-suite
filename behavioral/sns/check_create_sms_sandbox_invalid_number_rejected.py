"""create-sms-sandbox-invalid-number-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sms-sandbox-invalid-number-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

# A UK number, not a NANP (+1) number: NANP destinations now require a registered
# origination identity (10DLC/toll-free) to send even the sandbox OTP, which the
# verification account may not have, and that would mask the malformed-number
# boundary under test with an unrelated "no origination entities available" UserError.
# The 07700 900xxx range is reserved by Ofcom for fictional use, so it's never a
# routable subscriber -- safe as a real, supported-number positive control.
_VALID_NUMBER = "+447700900124"
_INVALID_NUMBER_MESSAGE = (
    'Invalid parameter: Validation Error Occurred - Reason="INVALID_PARAMETER" '
    'Fields="destinationPhoneNumber" (Service: PinpointSmsVoiceV2, Status Code: 400'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSMSSandboxPhoneNumber must reject a phone number that is not in E.164 format."""
    sns = ctx.client("sns")
    try:
        result = sns.create_sms_sandbox_phone_number(PhoneNumber="12345")
    except ClientError as exc:
        error = exc.response.get("Error", {})
    else:
        raise AssertionError(
            f"expected a rejection for a non-E.164 sandbox phone number, but the call SUCCEEDED: {result!r}"
        )
    code, message = error.get("Code"), error.get("Message")
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a non-E.164 sandbox phone number, got {code}"
    )
    # The message ends with the request id of SNS's downstream SMS call, which differs
    # from the SNS RequestId and from run to run; everything before it is asserted whole.
    _, sep, request_id = (message or "").rpartition(", Request ID: ")
    assert sep and len(request_id) == 37 and request_id.endswith(")"), (
        f"unexpected request id suffix for a non-E.164 sandbox phone number: {message!r}"
    )
    assert message == f"{_INVALID_NUMBER_MESSAGE}, Request ID: {request_id}", (
        f"unexpected message for a non-E.164 sandbox phone number: {message!r}"
    )

    listed = {n["PhoneNumber"] for n in sns.list_sms_sandbox_phone_numbers()["PhoneNumbers"]}
    assert "12345" not in listed, f"rejected sandbox number must not be persisted: {listed}"

    # Positive control: without this, the InvalidParameter above cannot be told
    # apart from CreateSMSSandboxPhoneNumber rejecting every call (no permission,
    # no origination entity, a broken target). A well-formed number must either
    # succeed (verified Pending) or fail for a DISTINCT, non-InvalidParameter
    # reason -- proving the malformed-number rejection is a specific, earlier
    # validation layer rather than a blanket failure.
    try:
        sns.create_sms_sandbox_phone_number(PhoneNumber=_VALID_NUMBER)
        code_valid = None
    except ClientError as exc:
        code_valid = exc.response.get("Error", {}).get("Code")

    if code_valid is None:
        ctx.on_cleanup(lambda: sns.delete_sms_sandbox_phone_number(PhoneNumber=_VALID_NUMBER))
        listed_after = _poll_listed(ctx, sns, _VALID_NUMBER, cap_s=20.0)
        assert listed_after.get(_VALID_NUMBER) == "Pending", (
            f"valid sandbox number missing/not Pending after creation: {listed_after}"
        )
    else:
        assert code_valid != "InvalidParameter", (
            f"a well-formed number must not fail with the same code as the malformed one, got {code_valid}"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_listed(ctx, sns, phone_number, cap_s):
    """Every listed sandbox number with its Status, re-read until phone_number appears or the cap ends."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        listed, token = {}, None
        while True:
            page = sns.list_sms_sandbox_phone_numbers(**({"NextToken": token} if token else {}))
            listed.update({n["PhoneNumber"]: n["Status"] for n in page.get("PhoneNumbers", [])})
            token = page.get("NextToken")
            if not token:
                break
        if phone_number in listed or time.monotonic() >= deadline:
            return listed
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
