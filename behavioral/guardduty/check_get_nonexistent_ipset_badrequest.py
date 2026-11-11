"""get-nonexistent-ipset-badrequest."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-ipset-badrequest"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """GetIPSet on a truly-unknown IPSet id is rejected with BadRequestException (not a stale/empty
    success), and a since-deleted IPSet id still resolves to a genuine terminal DELETE state --
    never to a silently-succeeding stale/active-looking payload."""
    gd = ctx.client("guardduty")
    detector_id = _create_detector_or_adopt(ctx, gd)

    location = f"s3://{ctx.unique_name('sim2real-behav-nonexistent-bucket-')}/list.txt"
    ip_set_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

    deleted_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=ctx.unique_name("sim2real-behav-ipset-del-"),
        Format="TXT",
        Location=location,
        Activate=False,
        Tags=ip_set_tags,
    )["IpSetId"]

    # positive control: freshly-created IPSet is readable and not yet in a terminal delete state
    before = gd.get_ip_set(DetectorId=detector_id, IpSetId=deleted_id)
    assert before["Status"] not in ("DELETE_PENDING", "DELETED"), (
        f"expected a non-terminal status right after creation, got {before['Status']!r}"
    )

    gd.delete_ip_set(DetectorId=detector_id, IpSetId=deleted_id)

    # state transition: GetIPSet on a deleted id keeps succeeding but must report a genuine
    # terminal delete status -- it must NEVER keep reporting a stale ACTIVE/INACTIVE payload,
    # and it must NEVER silently vanish into an empty/malformed success body.
    final_status = _poll_delete_status(gd, detector_id, deleted_id)
    assert final_status in ("DELETE_PENDING", "DELETED"), (
        f"expected a terminal delete status after DeleteIPSet, got {final_status!r}"
    )

    # mutation on the dead id also fails: an UpdateIPSet against the now-deleted id must never be
    # silently accepted as if the resource were still live (real GuardDuty answers
    # InternalServerErrorException here rather than a clean BadRequestException, but it must not
    # be a 200).
    _error(
        lambda: gd.update_ip_set(DetectorId=detector_id, IpSetId=deleted_id, Name="sim2real-should-not-apply")
    )

    # effect absent: the deleted IPSet id no longer appears in the detector's (non-deleted) IPSet list
    remaining_ids = gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", [])
    assert deleted_id not in remaining_ids, (
        f"expected {deleted_id!r} to be absent from list_ip_sets after delete, got {remaining_ids!r}"
    )

    # error-semantics: GetIPSet for an id that was NEVER created (well-formed but unknown) must be
    # rejected outright with BadRequestException, not returned as a stale/empty success payload.
    bogus_id = uuid.uuid4().hex
    assert bogus_id not in remaining_ids, f"unrelated bogus id {bogus_id!r} unexpectedly already listed"
    err = _error(lambda: gd.get_ip_set(DetectorId=detector_id, IpSetId=bogus_id))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    expected = "The request is rejected since no such resource found."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # positive control: GetIPSet on a separate, live (non-deleted) IPSet still succeeds normally
    live_name = ctx.unique_name("sim2real-behav-ipset-live-")
    live_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=live_name,
        Format="TXT",
        Location=location,
        Activate=False,
        Tags=ip_set_tags,
    )["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=live_id))
    live = gd.get_ip_set(DetectorId=detector_id, IpSetId=live_id)
    assert live["Name"] == live_name, f"expected live ipset name {live_name!r}, got {live['Name']!r}"
    assert live["Status"] not in ("DELETE_PENDING", "DELETED"), (
        f"expected the live ipset to not be in a terminal delete status, got {live['Status']!r}"
    )


def _create_detector_or_adopt(ctx, gd):
    """GuardDuty is one-detector-per-account-per-region. Adopt a pre-existing detector
    (leave it and its lifecycle untouched) rather than attempting a second CreateDetector,
    which real GuardDuty rejects with BadRequestException."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    detector_id = gd.create_detector(Enable=True, Tags=tags)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_delete_status(gd, detector_id: str, ip_set_id: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Status"]
        if last_status in ("DELETE_PENDING", "DELETED"):
            return last_status
        time.sleep(interval_s)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
