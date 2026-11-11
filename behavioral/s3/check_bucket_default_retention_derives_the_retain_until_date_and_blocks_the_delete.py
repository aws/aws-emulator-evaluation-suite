"""bucket-default-retention-derives-the-retain-until-date-and-blocks-the-delete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-default-retention-derives-the-retain-until-date-and-blocks-the-delete"
GROUP = "object_lock"
SERVICES = ["s3"]

_DAYS = 1
_DAY_S = 86400
# Absorbs clock skew between the client and S3.
_SKEW_TOLERANCE_S = 120.0
_BODY = b"object-lock-default-retention-payload"
_KEY = "locked/inherits-default.bin"


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An object inherits a GOVERNANCE default retention dated write time plus the period, and a version
    delete is refused until BypassGovernanceRetention; a twin bucket with no rule deletes cleanly.
    """
    s3 = ctx.client("s3")
    retained_bucket = _new_locked_bucket(ctx, s3)
    control_bucket = _new_locked_bucket(ctx, s3)

    s3.put_object_lock_configuration(
        Bucket=retained_bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": _DAYS}},
        },
    )
    cfg = s3.get_object_lock_configuration(Bucket=retained_bucket)["ObjectLockConfiguration"]
    assert cfg["Rule"]["DefaultRetention"] == {"Mode": "GOVERNANCE", "Days": _DAYS}, (
        f"GetObjectLockConfiguration reports {cfg.get('Rule')!r}; expected "
        f"{{'DefaultRetention': {{'Mode': 'GOVERNANCE', 'Days': {_DAYS}}}}}"
    )
    control_cfg = s3.get_object_lock_configuration(Bucket=control_bucket)["ObjectLockConfiguration"]
    assert "Rule" not in control_cfg, (
        f"the control bucket reports a default-retention rule {control_cfg.get('Rule')!r}; it must "
        "differ from the retained bucket in exactly this one respect"
    )

    # Bracket the write so the expected date derives from this run's own clock.
    written_before = time.time()
    retained_version = s3.put_object(Bucket=retained_bucket, Key=_KEY, Body=_BODY)["VersionId"]
    written_after = time.time()
    control_version = s3.put_object(Bucket=control_bucket, Key=_KEY, Body=_BODY)["VersionId"]

    # The expected date is an interval derived from the measured write time, not a pinned value.
    retention = s3.get_object_retention(
        Bucket=retained_bucket, Key=_KEY, VersionId=retained_version
    )["Retention"]
    assert retention["Mode"] == "GOVERNANCE", (
        f"the inherited retention mode is {retention['Mode']!r}, expected 'GOVERNANCE'"
    )
    retain_until = retention["RetainUntilDate"].timestamp()
    implied_write = retain_until - _DAYS * _DAY_S
    assert written_before - _SKEW_TOLERANCE_S <= implied_write <= written_after + _SKEW_TOLERANCE_S, (
        f"RetainUntilDate implies a write at epoch {implied_write:.0f} once the {_DAYS}-day default "
        f"period is subtracted, but the PutObject happened between {written_before:.0f} and "
        f"{written_after:.0f} (tolerance {_SKEW_TOLERANCE_S:.0f}s) — the retain-until date is not "
        "the write time plus the bucket's default period"
    )
    head = s3.head_object(Bucket=retained_bucket, Key=_KEY, VersionId=retained_version)
    assert head.get("ObjectLockMode") == "GOVERNANCE", (
        f"HeadObject reports ObjectLockMode {head.get('ObjectLockMode')!r}, expected 'GOVERNANCE' — "
        "GetObjectRetention and HeadObject disagree about the same version"
    )
    assert abs(head["ObjectLockRetainUntilDate"].timestamp() - retain_until) < 1.0, (
        f"HeadObject reports RetainUntilDate {head['ObjectLockRetainUntilDate']!r} while "
        f"GetObjectRetention reports {retention['RetainUntilDate']!r}"
    )

    # Twin control: no default rule means no retention at all.
    code, message = _client_error(
        lambda: s3.get_object_retention(
            Bucket=control_bucket, Key=_KEY, VersionId=control_version
        )
    )
    assert code == "NoSuchObjectLockConfiguration", (
        "the control object reports a retention even though its bucket has no DefaultRetention rule"
    )
    assert message == "The specified object does not have a ObjectLock configuration", f"unexpected message {message!r}"
    control_head = s3.head_object(Bucket=control_bucket, Key=_KEY, VersionId=control_version)
    assert "ObjectLockRetainUntilDate" not in control_head, (
        f"the control object carries ObjectLockRetainUntilDate "
        f"{control_head.get('ObjectLockRetainUntilDate')!r} with no default-retention rule in force"
    )

    code, message = _client_error(
        lambda: s3.delete_object(
            Bucket=retained_bucket, Key=_KEY, VersionId=retained_version
        )
    )
    assert code == "AccessDenied", (
        f"deleting version {retained_version} under an INHERITED governance retention was not "
        "refused with AccessDenied — the bucket default is stored but never consulted"
    )
    assert message == "Access Denied because object protected by object lock.", f"unexpected message {message!r}"
    assert s3.get_object(
        Bucket=retained_bucket, Key=_KEY, VersionId=retained_version
    )["Body"].read() == _BODY, (
        "the retained version's bytes changed even though the delete was refused"
    )

    # The same call on the control bucket succeeds, so the refusal is about the retention.
    s3.delete_object(Bucket=control_bucket, Key=_KEY, VersionId=control_version)
    # A HEAD response carries no body, so there is no AWS message to compare.
    code, _ = _client_error(
        lambda: s3.head_object(Bucket=control_bucket, Key=_KEY, VersionId=control_version)
    )
    assert code == "404", (
        f"the control version {control_version} survived a delete that carried no bypass (got {code!r})"
    )

    # The bypass flag lifts the block; the version is then gone and unusable.
    s3.delete_object(
        Bucket=retained_bucket,
        Key=_KEY,
        VersionId=retained_version,
        BypassGovernanceRetention=True,
    )
    code, _ = _client_error(
        lambda: s3.head_object(Bucket=retained_bucket, Key=_KEY, VersionId=retained_version)
    )
    assert code == "404", (
        f"version {retained_version} survived a delete carrying BypassGovernanceRetention=True (got {code!r})"
    )
    code, message = _client_error(
        lambda: s3.put_object_retention(
            Bucket=retained_bucket,
            Key=_KEY,
            VersionId=retained_version,
            Retention={
                "Mode": "GOVERNANCE",
                "RetainUntilDate": retention["RetainUntilDate"],
            },
        )
    )
    assert code == "NoSuchVersion", (
        f"PutObjectRetention still mutates the deleted version {retained_version} (got {code!r})"
    )
    assert message == "The specified version does not exist.", f"unexpected message {message!r}"


def _delete_bucket(client, bucket):
    """Teardown only: delete every version and delete marker, bypassing governance, then the bucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(
                    Bucket=bucket,
                    Key=o["Key"],
                    VersionId=o["VersionId"],
                    BypassGovernanceRetention=True,
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_locked_bucket(ctx, s3):
    """Create a uniquely-named, tagged, Object-Lock-enabled bucket with teardown registered."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name, "ObjectLockEnabledForBucket": True}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _client_error(fn) -> tuple[str, str | None]:
    """(Error.Code, Error.Message) of fn(), the code falling back to the HTTP status for a
    code-less HEAD; raises if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        if not code or code.isdigit():
            code = str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
        return code, err.get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
