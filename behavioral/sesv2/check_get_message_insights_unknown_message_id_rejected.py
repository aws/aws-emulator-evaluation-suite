"""get-message-insights-unknown-message-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-message-insights-unknown-message-id-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """With VDM enabled, GetMessageInsights rejects a malformed MessageId with BadRequestException
    "Invalid MessageId", and a shape-valid id addressing no message with NotFoundException."""
    ses = ctx.client("sesv2")

    # With VDM disabled every MessageId gets the same "enable VDM" NotFoundException, so the
    # shape stage is unreachable; VDM is enabled for the run and restored on cleanup.
    original_vdm = ses.get_account().get("VdmAttributes", {}).get("VdmEnabled")
    if original_vdm != "ENABLED":
        ses.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": "ENABLED"})
        _wait_for_vdm(ses, "ENABLED")
        ctx.on_cleanup(lambda: _restore_vdm(ses, original_vdm or "DISABLED"))

    garbage_message_id = "not-a-real-message-id-at-all"
    garbage_err = _error(lambda: ses.get_message_insights(MessageId=garbage_message_id))
    assert garbage_err.get("Code") == "BadRequestException", repr(garbage_err)
    assert garbage_err.get("Message") == "Invalid MessageId", (
        f"expected message 'Invalid MessageId', got {garbage_err.get('Message')!r}"
    )

    verified = [
        identity["IdentityName"]
        for identity in ses.list_email_identities().get("EmailIdentities", [])
        if identity.get("IdentityType") in ("EMAIL_ADDRESS", "DOMAIN")
        and identity.get("VerificationStatus") == "SUCCESS"
        and identity.get("SendingEnabled", True)
    ]
    # The not-found leg needs a real, decodable id, so it runs only with a verified identity.
    if not verified:
        return

    send_resp = ses.send_email(
        FromEmailAddress=verified[0],
        Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
        Content={
            "Simple": {
                "Subject": {"Data": "sim2real message-insights probe"},
                "Body": {"Text": {"Data": "sim2real probe"}},
            }
        },
    )
    real_message_id = send_resp["MessageId"]

    def _probe():
        try:
            return ses.get_message_insights(MessageId=real_message_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return None
            raise

    result = _poll_until(
        _probe, lambda r: r is not None, timeout_s=90.0, interval_s=5.0,
        description="GetMessageInsights resolving for a real sent message",
    )
    assert result["MessageId"] == real_message_id

    # Same decodable shape as the real id, but a suffix that addresses no real message.
    prefix, _, _suffix = real_message_id.rpartition("-")
    sibling_id = f"{prefix}-999999"
    sibling_err = _error(lambda: ses.get_message_insights(MessageId=sibling_id))
    # Only the code is asserted: the not-found message for this leg is not pinned.
    assert sibling_err["Code"] == "NotFoundException", repr(sibling_err)


def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"expected GetMessageInsights to reject this MessageId, but it SUCCEEDED and returned {result!r}"
    )


def _wait_for_vdm(ses, desired, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ses.get_account().get("VdmAttributes", {}).get("VdmEnabled")
        if last == desired:
            return
        time.sleep(interval_s)
    raise AssertionError(f"VdmEnabled never reached {desired!r} within {timeout_s}s; last saw {last!r}")


def _restore_vdm(ses, desired):
    ses.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": desired})
    _wait_for_vdm(ses, desired, timeout_s=45.0)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
