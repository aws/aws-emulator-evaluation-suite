"""get-secret-value-sets-last-accessed-date-to-the-day-without-changing-last-changed-date."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "get-secret-value-sets-last-accessed-date-to-the-day-without-changing-last-changed-date"
GROUP = "data-plane"
SERVICES = ["secretsmanager"]


def _utc(ts):
    return ts.astimezone(datetime.timezone.utc)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue stamps LastAccessedDate with the UTC day truncated to midnight, metadata reads
    do not set it, and reads leave LastChangedDate unchanged; unused-secret audits depend on
    LastAccessedDate."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-lastacc-")
    created = _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")

    fresh = sm.describe_secret(SecretId=name)
    changed_at_create = fresh["LastChangedDate"]
    assert "LastAccessedDate" not in fresh, (
        f"a never-read secret has no LastAccessedDate, got {fresh.get('LastAccessedDate')!r}"
    )
    sm.list_secret_version_ids(SecretId=name)
    metadata_only = sm.describe_secret(SecretId=name)
    assert "LastAccessedDate" not in metadata_only, (
        "DescribeSecret / ListSecretVersionIds are metadata reads and must not set "
        f"LastAccessedDate, got {metadata_only.get('LastAccessedDate')!r}"
    )

    value = sm.get_secret_value(SecretId=name)
    assert value["VersionId"] == created["VersionId"], "GetSecretValue must serve the created version"

    after = _poll(lambda: sm.describe_secret(SecretId=name), lambda d: "LastAccessedDate" in d,
                  timeout_s=60.0, interval_s=2.0)
    assert "LastAccessedDate" in after, "GetSecretValue must set LastAccessedDate"
    accessed = _utc(after["LastAccessedDate"])
    assert (accessed.hour, accessed.minute, accessed.second, accessed.microsecond) == (0, 0, 0, 0), (
        f"LastAccessedDate is truncated to the UTC day, got {accessed.isoformat()}"
    )
    created_day = _utc(after["CreatedDate"]).date()
    today = datetime.datetime.now(datetime.timezone.utc).date()
    assert created_day <= accessed.date() <= today, (
        f"LastAccessedDate {accessed.date()} must be the UTC day of the read, between the "
        f"creation day {created_day} and today {today}"
    )
    assert after["LastChangedDate"] == changed_at_create, (
        f"a read must not change LastChangedDate: {changed_at_create.isoformat()} -> "
        f"{after['LastChangedDate'].isoformat()}"
    )

    # A second read on the same day leaves the stamp where it was.
    sm.get_secret_value(SecretId=name)
    again = sm.describe_secret(SecretId=name)
    assert _utc(again["LastAccessedDate"]).date() >= accessed.date(), "LastAccessedDate went backwards"
    assert again["LastChangedDate"] == changed_at_create, "a second read must not change LastChangedDate"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
