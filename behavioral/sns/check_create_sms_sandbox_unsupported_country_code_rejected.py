"""create-sms-sandbox-unsupported-country-code-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sms-sandbox-unsupported-country-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["sns"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)

# "+0..." satisfies the API's pattern (^(\+[0-9]{8,}|[0-9]{0,9})$), but no E.164 calling
# code starts with 0: well-formed, yet an unsupported country code.
_UNSUPPORTED_COUNTRY_NUMBER = "+0123456789"
# A UK number, not NANP (+1): NANP destinations need a registered origination identity
# (10DLC/toll-free) even for the sandbox OTP, else an unrelated UserError. Ofcom reserves
# 07700 900xxx for fictional use, so it is never a routable subscriber.
_VALID_NUMBER = "+447700900125"



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSMSSandboxPhoneNumber refuses a number with an unassigned country code with
    InvalidParameter and does not list it; a real-country number never fails InvalidParameter."""
    sns = ctx.client("sns")

    code, message = _rejected_error(
        lambda: sns.create_sms_sandbox_phone_number(PhoneNumber=_UNSUPPORTED_COUNTRY_NUMBER),
        description=f"a well-formed but unsupported-country-code number ({_UNSUPPORTED_COUNTRY_NUMBER!r})",
    )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for unsupported-country-code number "
        f"{_UNSUPPORTED_COUNTRY_NUMBER!r}, got {code!r}"
    )
    # The message relays the internal downstream call, whose request id is the only varying part.
    expected = (
        "Invalid parameter: The following parameter is null, empty or invalid: "
        "['destinationPhoneNumber'] (Service: PinpointSmsVoiceV2, Status Code: 400, "
        "Request ID: <request-id>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}, got {message!r}"

    assert not _contains(sns, _UNSUPPORTED_COUNTRY_NUMBER, timeout_s=10.0), (
        f"rejected number {_UNSUPPORTED_COUNTRY_NUMBER!r} must not appear in "
        "list_sms_sandbox_phone_numbers, but it does"
    )

    # Succeeds, or fails later for a different reason when the account has no SMS
    # origination identity; both outcomes are legitimate.
    try:
        sns.create_sms_sandbox_phone_number(PhoneNumber=_VALID_NUMBER)
        code_valid = None
    except ClientError as e:
        code_valid = e.response["Error"]["Code"]
    if code_valid is None:
        ctx.on_cleanup(lambda: sns.delete_sms_sandbox_phone_number(PhoneNumber=_VALID_NUMBER))
        assert _contains(sns, _VALID_NUMBER, timeout_s=20.0), (
            f"accepted control number {_VALID_NUMBER!r} did not appear in "
            "list_sms_sandbox_phone_numbers within 20s"
        )
    else:
        assert code_valid != "InvalidParameter", (
            "a valid supported-country number must not fail the country-code check "
            f"(same InvalidParameter as the unsupported-country-code case); got {code_valid!r}"
        )



def _rejected_error(fn, *, description):
    """(Code, Message) of a call that is always invalid; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected {description} to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _contains(sns, phone_number, timeout_s=10.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        token = None
        while True:
            kwargs = {"NextToken": token} if token else {}
            page = sns.list_sms_sandbox_phone_numbers(**kwargs)
            for entry in page.get("PhoneNumbers", []):
                if entry["PhoneNumber"] == phone_number:
                    return True
            token = page.get("NextToken")
            if not token:
                break
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
