"""start-query-invalid-time-range-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "start-query-invalid-time-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["internetmonitor"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInternetEvents with StartTime after EndTime fails with ValidationException "Invalid time
    window specified", while the same call with the times in order returns an InternetEvents list."""
    im = ctx.client("internetmonitor")

    now = datetime.now(timezone.utc)
    later = now + timedelta(hours=1)

    code, message = _error(
        lambda: im.list_internet_events(StartTime=later, EndTime=now, MaxResults=10)
    )
    assert code == "ValidationException", f"unexpected error code for StartTime>EndTime: {code}"
    assert message == "Invalid time window specified", f"unexpected message for StartTime>EndTime: {message!r}"

    good = im.list_internet_events(
        StartTime=now - timedelta(hours=1), EndTime=now, MaxResults=10
    )
    assert isinstance(good["InternetEvents"], list), (
        f"expected a well-formed InternetEvents list for StartTime<EndTime, got: {good.get('InternetEvents')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
