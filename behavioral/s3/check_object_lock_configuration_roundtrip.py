"""object-lock-configuration-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-lock-configuration-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectLockConfiguration on a bucket created with Object Lock enabled sets a
    default retention mode/period and GetObjectLockConfiguration returns it
    unchanged."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-lockcfg-")
    _create_bucket(ctx, s3, name, ObjectLockEnabledForBucket=True)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    s3.put_object_lock_configuration(
        Bucket=name,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )

    got = s3.get_object_lock_configuration(Bucket=name)
    cfg = got["ObjectLockConfiguration"]
    assert cfg["ObjectLockEnabled"] == "Enabled", f"expected ObjectLockEnabled='Enabled', got {cfg!r}"
    retention = cfg["Rule"]["DefaultRetention"]
    assert retention["Mode"] == "GOVERNANCE", f"expected DefaultRetention.Mode='GOVERNANCE', got {retention!r}"
    assert retention["Days"] == 1, f"expected DefaultRetention.Days=1, got {retention!r}"


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
