"""object-retention-lifecycle."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-retention-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectRetention applies a retain-until-date/mode to an object and
    GetObjectRetention reflects the applied hold state exactly."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-retn-")
    key = "retention-test.txt"
    _create_bucket(ctx, s3, name, ObjectLockEnabledForBucket=True)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name, bypass_governance=True))

    s3.put_object(Bucket=name, Key=key, Body=b"retention-payload")

    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        hours=6
    )
    s3.put_object_retention(
        Bucket=name,
        Key=key,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )

    got = s3.get_object_retention(Bucket=name, Key=key)
    retention = got["Retention"]
    assert retention["Mode"] == "GOVERNANCE", retention
    delta = abs((retention["RetainUntilDate"] - retain_until).total_seconds())
    assert delta < 5, (
        f"RetainUntilDate drifted by {delta}s: {retention['RetainUntilDate']} vs {retain_until}"
    )


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    # us-east-1 literal: CreateBucket rejects an explicit LocationConstraint for that region,
    # so it must be omitted rather than passed — not a region pin.
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
