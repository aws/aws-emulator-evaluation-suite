"""create-ipset-malformed-s3-location-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ipset-malformed-s3-location-rejected"
GROUP = "negative-classes"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateIPSet with a malformed Location raises BadRequestException with the exact message and
    adds no IPSet, while a valid S3 Location creates one that GetIPSet returns.
    """
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    before = set(gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", []))

    code, message = _error_code(
        lambda: gd.create_ip_set(
            DetectorId=detector_id,
            Name=ctx.unique_name("sim2real-gd-ipset-bad-"),
            Format="TXT",
            Location="this is not a valid s3 uri or arn",
            Activate=False,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = "The request is rejected because the parameter ipSetLocation has an invalid value."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no IPSet was provisioned by the rejected attempt
    after = set(gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", []))
    assert after == before, (
        f"rejected CreateIPSet must not provision anything: before={before!r} after={after!r}"
    )

    # positive control: a syntactically valid S3 location succeeds
    name = ctx.unique_name("sim2real-gd-ipset-good-")
    good_location = f"s3://{ctx.unique_name('sim2real-gd-ipset-bucket-')}/list.txt"
    ip_set_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=good_location,
        Activate=False,
    )["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))
    got_location = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Location"]
    assert got_location == good_location, (
        f"expected Location {good_location!r} on the accepted IPSet, got {got_location!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a Location real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected BadRequestException for a malformed Location, but the call "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
