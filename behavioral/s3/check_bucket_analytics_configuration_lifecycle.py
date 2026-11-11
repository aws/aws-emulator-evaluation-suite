"""bucket-analytics-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-analytics-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]

_NO_SUCH_CONFIGURATION_MESSAGE = "The specified configuration does not exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketAnalyticsConfiguration creates a named config visible in both
    ListBucketAnalyticsConfigurations and GetBucketAnalyticsConfiguration;
    DeleteBucketAnalyticsConfiguration removes it from both."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-analytics-")
    config_id = "config-1"
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    s3.put_bucket_analytics_configuration(
        Bucket=name,
        Id=config_id,
        AnalyticsConfiguration={
            "Id": config_id,
            "StorageClassAnalysis": {},
        },
    )

    got = s3.get_bucket_analytics_configuration(Bucket=name, Id=config_id)
    assert got["AnalyticsConfiguration"]["Id"] == config_id, got

    listed = s3.list_bucket_analytics_configurations(Bucket=name)
    ids = [c["Id"] for c in listed.get("AnalyticsConfigurationList", [])]
    assert ids == [config_id], f"expected exactly [{config_id!r}] listed on a fresh bucket, got {ids}"

    s3.delete_bucket_analytics_configuration(Bucket=name, Id=config_id)

    code, message = _client_error(lambda: s3.get_bucket_analytics_configuration(Bucket=name, Id=config_id))
    assert code == "NoSuchConfiguration", code
    assert message == _NO_SUCH_CONFIGURATION_MESSAGE, f"unexpected message {message!r}"

    listed2 = s3.list_bucket_analytics_configurations(Bucket=name)
    ids2 = [c["Id"] for c in listed2.get("AnalyticsConfigurationList", [])]
    assert ids2 == [], f"expected no analytics configurations after delete, got {ids2}"

    # A second delete on the now-dead id must also fail, not silently no-op: it proves the
    # id is genuinely gone rather than merely absent from the last read.
    redelete_code, redelete_message = _client_error(
        lambda: s3.delete_bucket_analytics_configuration(Bucket=name, Id=config_id)
    )
    assert redelete_code == "NoSuchConfiguration", redelete_code
    assert redelete_message == _NO_SUCH_CONFIGURATION_MESSAGE, f"unexpected message {redelete_message!r}"


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    # us-east-1 is S3's region-pinned default: CreateBucket rejects an explicit
    # LocationConstraint there and requires one everywhere else.
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
