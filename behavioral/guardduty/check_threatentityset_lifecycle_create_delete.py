"""threatentityset-lifecycle-create-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "threatentityset-lifecycle-create-delete"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateThreatEntitySet is immediately retrievable (Status ACTIVATING/ACTIVE);
    DeleteThreatEntitySet is refused with ConflictException while the set is ACTIVATING,
    and an accepted delete ends with GetThreatEntitySet refusing ResourceNotFoundException."""
    gd = ctx.client("guardduty")
    detector_id, _ = _get_or_create_detector(ctx)
    bucket, key = _make_list_bucket(ctx, ["malicious.example.com", "203.0.113.9"])

    name = ctx.unique_name("sim2real-tes-")[:64]
    resp = gd.create_threat_entity_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=f"s3://{bucket}/{key}",
        Activate=True,
        Tags={"sim2real-check": CHECK},
    )
    entity_set_id = resp["ThreatEntitySetId"]
    ctx.on_cleanup(lambda: _safe_delete(gd, detector_id, entity_set_id))

    got = gd.get_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=entity_set_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Status"] in ("ACTIVATING", "ACTIVE"), f"unexpected initial status {got['Status']}"

    try:
        gd.delete_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=entity_set_id)
    except ClientError as err:
        # Deleting while the resource is still ACTIVATING is itself a documented, valid
        # state-machine rejection ("can't perform any action" while Activating).
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ConflictException", (
            f"expected ConflictException when deleting a still-ACTIVATING resource, got {code}"
        )
        expected = "Another operation is currently in progress, please wait until it completes, then try again."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        still_there = gd.get_threat_entity_set(
            DetectorId=detector_id, ThreatEntitySetId=entity_set_id
        )
        assert still_there["Status"] != "DELETED", (
            f"delete was rejected with ConflictException but an independent read shows "
            f"Status {still_there['Status']!r} == DELETED"
        )
        return

    # An accepted delete passes through DELETE_PENDING, which can last many minutes.
    code, message = _wait_until_refused(
        lambda: gd.get_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=entity_set_id),
        timeout_s=1200,
        interval_s=10,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected = "The specified entity set does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====


def _get_or_create_detector(ctx):
    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(Enable=True, Tags={"sim2real-check": CHECK})
    detector_id = resp["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id, True


def _make_list_bucket(ctx, lines):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-gd-list-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    key = "list.txt"
    body = ("\n".join(lines) + "\n").encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body, Tagging=f"sim2real-check={CHECK}")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket, key


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _wait_for_error_code(call, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as e:
            return e.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(f"call never failed within {timeout_s}s (last_code={last_code})")


def _wait_until_refused(call, *, timeout_s, interval_s):
    """(code, message) of the first refusal of call(); a call still answering at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = call().get("Status")
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"entity set still readable {timeout_s}s after delete (Status {last!r})")
        time.sleep(interval_s)


def _safe_delete(gd, detector_id, entity_set_id, timeout_s=840.0, interval_s=15.0):
    """Delete the set, waiting out the ConflictException GuardDuty answers while it is ACTIVATING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gd.delete_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=entity_set_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

