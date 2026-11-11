"""bucket-intelligent-tiering-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-intelligent-tiering-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put creates a named Intelligent-Tiering config visible via List/Get; Delete removes it from both."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-tier-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    config_id = ctx.unique_name("tiercfg-")
    tierings = [
        {"Days": 90, "AccessTier": "ARCHIVE_ACCESS"},
        {"Days": 180, "AccessTier": "DEEP_ARCHIVE_ACCESS"},
    ]
    tiering_cfg = {
        "Id": config_id,
        "Status": "Enabled",
        "Tierings": tierings,
    }
    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id=config_id, IntelligentTieringConfiguration=tiering_cfg
    )

    got = s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=config_id)
    cfg = got["IntelligentTieringConfiguration"]
    assert cfg["Id"] == config_id, f"expected Id {config_id!r}, got {cfg!r}"
    assert cfg["Status"] == "Enabled", f"expected Status Enabled, got {cfg!r}"
    assert cfg["Tierings"] == tierings, f"expected Tierings {tierings!r} preserved verbatim, got {cfg['Tierings']!r}"

    listed = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    ids = [c["Id"] for c in listed.get("IntelligentTieringConfigurationList", [])]
    assert ids == [config_id], f"expected exactly [{config_id!r}] listed, got {ids}"

    s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=config_id)

    code, message = _client_error(lambda: s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id=config_id))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration after delete, got {code}"
    expected = "The specified configuration does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    ids_after = [c["Id"] for c in listed_after.get("IntelligentTieringConfigurationList", [])]
    assert config_id not in ids_after, f"config {config_id} still listed after delete: {ids_after}"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 (it is the implicit
        # default), so the constraint is only ever sent for every other region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
