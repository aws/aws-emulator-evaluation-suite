"""object-retention-shorten-governance-without-bypass-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-retention-shorten-governance-without-bypass-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Shortening a GOVERNANCE-mode retention period without BypassGovernanceRetention
    must be rejected with AccessDenied -- retention can only ever be tightened or
    bypassed explicitly, never silently loosened."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-retnshort-")
    key = "retention-shorten-test.txt"
    _create_bucket(ctx, s3, name, ObjectLockEnabledForBucket=True)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name, bypass_governance=True))

    s3.put_object(Bucket=name, Key=key, Body=b"retention-shorten-payload")

    now = datetime.datetime.now(datetime.timezone.utc)
    original_until = now + datetime.timedelta(days=2)
    shortened_until = now + datetime.timedelta(hours=1)
    s3.put_object_retention(
        Bucket=name,
        Key=key,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": original_until},
    )

    code, message = _client_error(
        lambda: s3.put_object_retention(
            Bucket=name,
            Key=key,
            Retention={"Mode": "GOVERNANCE", "RetainUntilDate": shortened_until},
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied shortening a GOVERNANCE RetainUntilDate without bypass, got {code}"
    assert message == "Access Denied because object protected by object lock.", f"unexpected message {message!r}"

    # Effect absent: the rejected attempt must not have moved the retention date at all.
    unchanged = s3.get_object_retention(Bucket=name, Key=key)["Retention"]
    assert unchanged["Mode"] == "GOVERNANCE", (
        f"the rejected shorten attempt changed the retention mode to {unchanged['Mode']!r}"
    )
    assert unchanged["RetainUntilDate"] >= original_until - datetime.timedelta(seconds=5), (
        f"the rejected shorten attempt moved RetainUntilDate to {unchanged['RetainUntilDate']!r}, "
        f"want it unchanged at (or after) {original_until!r}"
    )

    # With BypassGovernanceRetention explicitly set, the identical shorten now succeeds.
    s3.put_object_retention(
        Bucket=name,
        Key=key,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": shortened_until},
        BypassGovernanceRetention=True,
    )
    got = s3.get_object_retention(Bucket=name, Key=key)["Retention"]
    assert got["Mode"] == "GOVERNANCE", got
    assert abs((got["RetainUntilDate"] - shortened_until).total_seconds()) <= 5, (
        f"the bypassed shorten left RetainUntilDate at {got['RetainUntilDate']!r}, "
        f"want it near the requested {shortened_until!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
