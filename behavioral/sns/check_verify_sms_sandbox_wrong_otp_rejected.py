"""verify-sms-sandbox-wrong-otp-rejected."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags

CHECK = "verify-sms-sandbox-wrong-otp-rejected"
GROUP = "overly-permissive"
SERVICES = ["sns"]

# A UK number, not a NANP (+1) number: NANP destinations now require a registered
# origination identity (10DLC/toll-free) to send even the sandbox OTP. The 07700
# 900xxx range is reserved by Ofcom for fictional/dramatic use, so it's syntactically
# valid but never a routable subscriber -- it can only ever be verified with a wrong
# code, which is exactly what we want.
#
# The origination-identity gate is not NANP-specific: on an account with no
# origination identity, CreateSMSSandboxPhoneNumber raises UserError ("No
# origination entities available to send") for this UK number too. That failure is
# send-only: the number is still registered server-side as Pending despite the
# raised UserError. So the UserError is tolerated here rather than treated as fatal, and Pending is
# confirmed independently via list, which is what the rest of this check depends on.
# Both numbers are drawn per run from that range, so concurrent runs in one account never share
# a sandbox entry.
_RESERVED_PREFIX = "+447700900"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Verifying a pending SMS sandbox phone number with an incorrect OTP is rejected
    with VerificationException, leaves the number's status at Pending (not Verified),
    and is a distinct error class from verifying a number that was never added."""

    pending_suffix, never_added_suffix = random.SystemRandom().sample(range(1000), 2)
    pending_number = f"{_RESERVED_PREFIX}{pending_suffix:03d}"
    never_added_number = f"{_RESERVED_PREFIX}{never_added_suffix:03d}"
    sns = ctx.client("sns")
    try:
        sns.create_sms_sandbox_phone_number(PhoneNumber=pending_number)
    except Exception as exc:  # noqa: BLE001 -- classify below
        code = _client_error_code(exc)
        # Without an origination identity the confirmation OTP can't be dispatched,
        # but the number still lands in Pending server-side, so this is not fatal to
        # the boundary under test.
        if code != "UserError":
            raise
    ctx.on_cleanup(lambda: _delete_if_present(sns, pending_number))

    # Positive control: the number reached Pending, regardless of whether the create
    # call itself raised.
    status = _sandbox_status(sns, pending_number)
    assert status == "Pending", f"expected {pending_number} to be Pending, got {status}"

    # Break exactly one thing: verify with a wrong OTP.
    code, message = _error(
        lambda: sns.verify_sms_sandbox_phone_number(
            PhoneNumber=pending_number, OneTimePassword="000000"
        )
    )
    assert code == "VerificationException", f"expected VerificationException, got {code}"
    assert message == "Verification code has expired, cannot verify the destination phone number.", (
        f"unexpected VerificationException message: {message!r}"
    )

    # Effect absent: the number did not transition to Verified.
    status = _sandbox_status(sns, pending_number)
    assert status == "Pending", f"expected {pending_number} to remain Pending, got {status}"

    # Distinct boundary: verifying a number that was never added at all is a different
    # error class (ResourceNotFound), not the same VerificationException.
    code_unknown, message_unknown = _error(
        lambda: sns.verify_sms_sandbox_phone_number(
            PhoneNumber=never_added_number, OneTimePassword="000000"
        )
    )
    assert code_unknown == "ResourceNotFound", f"expected ResourceNotFound, got {code_unknown}"
    assert message_unknown == "Resource does not exist", (
        f"unexpected ResourceNotFound message: {message_unknown!r}"
    )

    # The cleanup delete is already mandatory; pull it into the body so it's a proven
    # negative rather than an unasserted teardown. Deletes prove gone and unusable.
    sns.delete_sms_sandbox_phone_number(PhoneNumber=pending_number)
    assert _sandbox_absent(sns, pending_number), (
        f"{pending_number} must not still appear in the sandbox list after delete"
    )
    code_deleted, message_deleted = _error(
        lambda: sns.verify_sms_sandbox_phone_number(
            PhoneNumber=pending_number, OneTimePassword="000000"
        )
    )
    assert code_deleted == "ResourceNotFound", (
        f"expected ResourceNotFound verifying a deleted number, got {code_deleted}"
    )
    assert message_deleted == "Resource does not exist", (
        f"unexpected ResourceNotFound message: {message_deleted!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _delete_if_present(sns, phone_number):
    """Teardown: the body deletes the number itself, so only a still-present number is deleted."""
    from botocore.exceptions import ClientError

    try:
        sns.delete_sms_sandbox_phone_number(PhoneNumber=phone_number)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _client_error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return type(exc).__name__


def _sandbox_status(sns, phone_number, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        token = None
        while True:
            kwargs = {"NextToken": token} if token else {}
            page = sns.list_sms_sandbox_phone_numbers(**kwargs)
            for entry in page.get("PhoneNumbers", []):
                if entry["PhoneNumber"] == phone_number:
                    last_seen = entry["Status"]
                    return last_seen
            token = page.get("NextToken")
            if not token:
                break
        time.sleep(interval_s)
    raise AssertionError(f"phone number {phone_number} never appeared in sandbox list")


def _sandbox_absent(sns, phone_number, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        token = None
        found = False
        while True:
            kwargs = {"NextToken": token} if token else {}
            page = sns.list_sms_sandbox_phone_numbers(**kwargs)
            if any(entry["PhoneNumber"] == phone_number for entry in page.get("PhoneNumbers", [])):
                found = True
                break
            token = page.get("NextToken")
            if not token:
                break
        if not found:
            return True
        time.sleep(interval_s)
    raise AssertionError(f"phone number {phone_number} still present in sandbox list after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
