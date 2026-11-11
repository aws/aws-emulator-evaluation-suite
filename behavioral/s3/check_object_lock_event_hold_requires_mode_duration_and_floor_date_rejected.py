"""object-lock-event-hold-requires-mode-duration-and-floor-date-rejected."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-lock-event-hold-requires-mode-duration-and-floor-date-rejected"
GROUP = "object-lock"
SERVICES = ["s3"]

_MODE_REQUIRED_MSG = "x-amz-object-lock-mode is required when x-amz-object-lock-event-hold is supplied."
_DURATION_REQUIRED_MSG = (
    "x-amz-object-lock-event-hold:ON must be supplied with exactly one event hold duration "
    "(days or years)."
)
_FLOOR_MSG = "The retain until date must be equal to or later than the current time plus the event hold duration."


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Placing an object under an Object Lock event hold requires a retention Mode and
    exactly one event hold duration, and the retain-until date must already cover the
    hold duration; HeadObject and GetObject round-trip the hold state and can release it.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-evthold-")
    _create_bucket(ctx, s3, bucket, ObjectLockEnabledForBucket=True)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    held_key = "event-held.txt"
    now = datetime.datetime.now(datetime.timezone.utc)
    retain_until = (now + datetime.timedelta(days=2, minutes=10)).replace(microsecond=0)

    put = s3.put_object(
        Bucket=bucket, Key=held_key, Body=b"payload",
        ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=retain_until,
        ObjectLockEventHold="ON", ObjectLockEventHoldDurationDays=1,
    )
    version_id = put["VersionId"]

    for label, resp in (("HeadObject", s3.head_object(Bucket=bucket, Key=held_key)),
                         ("GetObject", s3.get_object(Bucket=bucket, Key=held_key))):
        try:
            assert resp.get("ObjectLockMode") == "GOVERNANCE", f"{label} mode {resp.get('ObjectLockMode')!r}"
            assert resp.get("ObjectLockEventHold") == "ON", f"{label} event hold {resp.get('ObjectLockEventHold')!r}"
            assert resp.get("ObjectLockEventHoldDurationDays") == 1, (
                f"{label} duration days {resp.get('ObjectLockEventHoldDurationDays')!r}"
            )
            got_until = resp.get("ObjectLockRetainUntilDate")
            assert got_until is not None and abs((got_until - retain_until).total_seconds()) <= 2, (
                f"{label} retain-until {got_until!r}, expected near {retain_until!r}"
            )
        finally:
            if "Body" in resp:
                resp["Body"].close()

    s3.put_object_retention(
        Bucket=bucket, Key=held_key, VersionId=version_id,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until, "EventHold": "OFF"},
    )
    released = s3.head_object(Bucket=bucket, Key=held_key)
    assert released.get("ObjectLockEventHold") == "OFF", (
        f"releasing the hold left ObjectLockEventHold={released.get('ObjectLockEventHold')!r}"
    )
    assert released.get("ObjectLockMode") == "GOVERNANCE", (
        f"releasing the hold must not change the retention mode, got {released.get('ObjectLockMode')!r}"
    )

    code, message = _error(lambda: s3.put_object(
        Bucket=bucket, Key="no-mode.txt", Body=b"x", ObjectLockEventHold="ON",
    ))
    assert code == "InvalidRequest", f"event hold without a mode must be InvalidRequest, got {code!r}"
    assert message == _MODE_REQUIRED_MSG, f"unexpected message {message!r}"

    code, message = _error(lambda: s3.put_object(
        Bucket=bucket, Key="no-duration.txt", Body=b"x",
        ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=retain_until,
        ObjectLockEventHold="ON",
    ))
    assert code == "InvalidRequest", f"event hold without a duration must be InvalidRequest, got {code!r}"
    assert message == _DURATION_REQUIRED_MSG, f"unexpected message {message!r}"

    too_early = (now + datetime.timedelta(minutes=30)).replace(microsecond=0)
    code, message, arg_name, arg_value = _error_with_argument(lambda: s3.put_object(
        Bucket=bucket, Key="too-early.txt", Body=b"x",
        ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=too_early,
        ObjectLockEventHold="ON", ObjectLockEventHoldDurationDays=1,
    ))
    assert code == "InvalidArgument", f"a retain-until date under the hold floor must be InvalidArgument, got {code!r}"
    assert message == _FLOOR_MSG, f"unexpected message {message!r}"
    assert arg_name == "x-amz-object-lock-retain-until-date", f"unexpected ArgumentName {arg_name!r}"
    assert arg_value == too_early.strftime("%Y-%m-%dT%H:%M:%SZ"), f"unexpected ArgumentValue {arg_value!r}"

    listed = _list_keys(s3, bucket)
    assert listed == [held_key], f"a refused creation left the bucket listing {listed!r}"


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Release any event hold, delete every object version and delete marker (bypassing
    governance locks), then the bucket; raise on any failure but NoSuchBucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            for v in page.get("Versions") or []:
                _release_event_hold(s3, name, v["Key"], v["VersionId"])
            to_delete = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                         for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
            if to_delete:
                failed = s3.delete_objects(
                    Bucket=name, Delete={"Objects": to_delete}, BypassGovernanceRetention=True,
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _release_event_hold(s3, bucket: str, key: str, version_id: str) -> None:
    """A held version cannot be deleted even with governance bypass, so turn its hold off first,
    keeping its mode and retain-until date."""
    try:
        retention = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)["Retention"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchKey", "NoSuchVersion", "NoSuchObjectLockConfiguration"):
            return
        raise
    if retention.get("EventHold") != "ON":
        return
    s3.put_object_retention(
        Bucket=bucket, Key=key, VersionId=version_id, BypassGovernanceRetention=True,
        Retention={"Mode": retention["Mode"], "RetainUntilDate": retention["RetainUntilDate"],
                   "EventHold": "OFF"},
    )


def _list_keys(s3, bucket: str) -> list[str]:
    """Every key, paginated."""
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents") or [])
    return sorted(keys)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; raises AssertionError on an unexpected
    success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _error_with_argument(fn) -> tuple[str, str, str, str]:
    """(code, message, ArgumentName, ArgumentValue) of the ClientError fn() raises; raises
    AssertionError on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), err.get("ArgumentName"), err.get("ArgumentValue")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
