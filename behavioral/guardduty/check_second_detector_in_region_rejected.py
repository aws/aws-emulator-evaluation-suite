"""second-detector-in-region-rejected."""
from __future__ import annotations

CHECK = "second-detector-in-region-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]

from behavioral_harness import tags

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A second CreateDetector fails with BadRequestException and its exact message, creates no
    detector and leaves the first one's status unchanged; when the check owns that detector, deleting
    it (GetDetector then fails exactly) lets the identical call create a new ENABLED detector."""
    gd = ctx.client("guardduty")
    detector_id, owned = _get_or_create_detector(ctx, gd)
    if owned:
        ctx.on_cleanup(lambda: _delete_detector_if_present(gd, detector_id))

    before_ids = set(gd.list_detectors().get("DetectorIds", []))
    assert detector_id in before_ids, f"expected {detector_id!r} in ListDetectors, got {before_ids!r}"

    initial_status = gd.get_detector(DetectorId=detector_id)["Status"]

    err = _error(lambda: gd.create_detector(Enable=True))
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException for a second CreateDetector, got {err!r}"
    )
    expected = "The request is rejected because a detector already exists for the current account."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    after_ids = set(gd.list_detectors().get("DetectorIds", []))
    assert after_ids == before_ids, "a second detector was created despite the rejection"

    # positive control: the original detector is unaffected and still usable
    detector = gd.get_detector(DetectorId=detector_id)
    assert detector["Status"] == initial_status, (
        f"expected the pre-existing detector's status to be untouched by the rejected call "
        f"({initial_status!r}), got {detector['Status']!r}"
    )

    if not owned:
        return

    # restore: remove the only thing the rejection depends on (a detector already existing)
    # and prove the identical call now succeeds. Only attempted when this check created the
    # sole detector itself, so no other check's state is touched.
    gd.delete_detector(DetectorId=detector_id)
    gone = _error(lambda: gd.get_detector(DetectorId=detector_id))
    assert gone["Code"] == "BadRequestException", (
        f"expected the deleted detector to read back as gone (BadRequestException), got {gone!r}"
    )
    expected_gone = "The request is rejected because the input detectorId is not owned by the current account."
    assert gone["Message"] == expected_gone, (
        f"expected message {expected_gone!r}, got {gone['Message']!r}"
    )

    restored_id = gd.create_detector(Enable=True, Tags=dict(_TAGS))["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=restored_id))

    restored = gd.get_detector(DetectorId=restored_id)
    assert restored["Status"] == "ENABLED", (
        f"expected CreateDetector to succeed once the blocking detector was removed, "
        f"got status {restored['Status']!r}"
    )


def _get_or_create_detector(ctx, gd):
    from botocore.exceptions import ClientError

    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    try:
        detector_id = gd.create_detector(
            Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES", Tags=dict(_TAGS)
        )["DetectorId"]
        return detector_id, True
    except ClientError:
        existing = gd.list_detectors().get("DetectorIds", [])
        if existing:
            return existing[0], False
        raise


def _delete_detector_if_present(gd, detector_id):
    """Teardown: the restore leg may already have deleted this detector."""
    from botocore.exceptions import ClientError

    try:
        gd.delete_detector(DetectorId=detector_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "BadRequestException":
            raise


def _error(fn):
    """Call fn(); return its botocore Error dict; an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
