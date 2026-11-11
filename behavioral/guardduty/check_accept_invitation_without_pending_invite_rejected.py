"""accept-invitation-without-pending-invite-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accept-invitation-without-pending-invite-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """AcceptInvitation is rejected with BadRequestException when no invitation from
    the given administrator account is pending."""
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    fake_master_id = "111122223333"
    fake_invitation_id = "sim2real-bogus-invitation-id"
    code, message = _error_code(
        lambda: gd.accept_invitation(
            DetectorId=detector_id,
            MasterId=fake_master_id,
            InvitationId=fake_invitation_id,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = (
        "The request is rejected because an invalid or out-of-range value is specified as an "
        "input parameter."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: no administrator relationship was established.
    master = gd.get_master_account(DetectorId=detector_id).get("Master", {})
    assert "AccountId" not in master, f"expected no administrator relationship, got {master!r}"

    # Positive control: the detector itself is otherwise fully functional -- a
    # normal read against it succeeds. This rules out an emulator that rejects
    # AcceptInvitation only because everything against this detector is broken.
    detector = gd.get_detector(DetectorId=detector_id)
    assert detector["Status"] == "ENABLED", f"expected detector ENABLED, got {detector['Status']!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected AcceptInvitation to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
