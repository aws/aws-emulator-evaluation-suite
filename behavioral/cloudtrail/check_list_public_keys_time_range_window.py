"""list-public-keys-time-range-window."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-public-keys-time-range-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPublicKeys only returns digest-signing keys whose validity window overlaps StartTime/EndTime."""
    ct = ctx.client("cloudtrail")
    now = datetime.now(timezone.utc)
    recent_start = now - timedelta(days=2)

    recent = ct.list_public_keys(StartTime=recent_start, EndTime=now)
    keys = recent.get("PublicKeyList", [])
    assert len(keys) >= 1, "expected at least one CloudTrail digest-signing public key in the last 2 days"
    for key in keys:
        assert key["ValidityStartTime"] <= now, (
            f"key validity start {key['ValidityStartTime']} is after the requested window end {now}"
        )
        assert key["ValidityEndTime"] >= recent_start, (
            f"key validity end {key['ValidityEndTime']} is before the requested window start {recent_start}"
        )

    # a window that predates CloudTrail's existence must overlap no key at all
    ancient_start = datetime(2005, 1, 1, tzinfo=timezone.utc)
    ancient_end = datetime(2005, 1, 2, tzinfo=timezone.utc)
    ancient = ct.list_public_keys(StartTime=ancient_start, EndTime=ancient_end)
    assert ancient.get("PublicKeyList", []) == [], (
        f"expected no keys valid in 2005, got {ancient.get('PublicKeyList')}"
    )

    # negative: an inverted time range (start after end) is rejected, not silently reordered
    code, message = _error(lambda: ct.list_public_keys(StartTime=now, EndTime=now - timedelta(days=1)))
    assert code == "InvalidTimeRangeException", f"expected InvalidTimeRangeException, got {code}"
    assert message == "Invalid input parameter! Start time is after end time", message


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected InvalidTimeRangeException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
