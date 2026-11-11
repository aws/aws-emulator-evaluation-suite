"""create-second-detector-in-account-region-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-second-detector-in-account-region-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A second CreateDetector in a region that already has a detector fails with
    BadRequestException and its exact message; ListDetectors still lists only the
    existing detector, whose status is unchanged."""
    gd = ctx.client("guardduty")

    before_ids = set(gd.list_detectors().get("DetectorIds", []))
    if before_ids:
        # account/region already has a detector from outside this check's own setup;
        # use it as the reference detector for the conflict assertion.
        detector_id = next(iter(before_ids))
    else:
        detector_id = gd.create_detector(Enable=True, Tags={"simparity-check": CHECK})["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        before_ids = {detector_id}

    before_status = gd.get_detector(DetectorId=detector_id)["Status"]

    code, message = _error_code(lambda: gd.create_detector(Enable=True))
    assert code == "BadRequestException", (
        f"expected BadRequestException from the conflicting CreateDetector, got {code!r}"
    )
    expected_message = "The request is rejected because a detector already exists for the current account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no new detector was provisioned by the rejected attempt
    after_ids = set(gd.list_detectors().get("DetectorIds", []))
    assert after_ids == before_ids, (
        f"a second detector appeared in ListDetectors: before={before_ids} after={after_ids}"
    )

    # positive control: the pre-existing detector is unaffected and still describable,
    # and its status is exactly what it was before the rejected attempt -- not merely
    # "some value from GuardDuty's two-value Status enum", which no target could fail.
    after_status = gd.get_detector(DetectorId=detector_id)["Status"]
    assert after_status == before_status, (
        f"detector status changed across the rejected create: before={before_status!r} after={after_status!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
