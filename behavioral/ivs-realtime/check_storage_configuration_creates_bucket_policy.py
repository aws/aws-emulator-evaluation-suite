"""storage-configuration-creates-bucket-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-configuration-creates-bucket-policy"
GROUP = "deploy"
SERVICES = ["ivs-realtime"]


def _create_storage_configuration_with_retry(ivs, timeout_s=90.0, interval_s=5.0, **kwargs):
    """StorageConfigurations are capped at 5 per account/region -- when several checks in
    this suite create one concurrently, a transient ServiceQuotaExceededException is
    expected while another check's storage config is still being torn down. Retry with a
    bounded backoff instead of treating that as the emulator-fidelity fact under test."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ivs.create_storage_configuration(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStorageConfiguration grants IVS write access by adding a statement to the
    target S3 bucket's policy (per IVS docs: "IVS will get access to write content to
    the specified S3 bucket ... by making modifications to the S3 bucket's policy")."""
    s3 = ctx.client("s3")
    ivs = ctx.client("ivs-realtime")

    # Reclaim quota headroom: StorageConfigurations are capped at 5/account, so purge any
    # leftover sim2real-* configs orphaned by earlier runs before creating a new one.
    for cfg in ivs.list_storage_configurations().get("storageConfigurations", []):
        if (cfg.get("name") or "").startswith("sim2real"):
            try:
                ivs.delete_storage_configuration(arn=cfg["arn"])
            except ClientError:
                pass

    bucket = ctx.unique_name("sim2real-ivsrt-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "env", "Value": "sim2real"}]}
    )

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    # No policy should exist on a brand-new bucket.
    try:
        s3.get_bucket_policy(Bucket=bucket)
        had_policy_before = True
    except ClientError as e:
        assert e.response["Error"]["Code"] == "NoSuchBucketPolicy", e.response["Error"]["Code"]
        assert e.response["Error"].get("Message") == "The bucket policy does not exist", (
            e.response["Error"].get("Message")
        )
        had_policy_before = False
    assert not had_policy_before, "bucket already carried a policy before CreateStorageConfiguration ran"

    storage_arn = _create_storage_configuration_with_retry(
        ivs,
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"env": "sim2real"},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    # CreateStorageConfiguration adds a statement scoped to
    # exactly this bucket's objects, granting an ivs-composite service principal write
    # access under a bucket-owner-full-control / TLS-only condition -- not just "a
    # statement mentioning ivs somewhere".
    policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    bucket_objects_arn = f"arn:aws:s3:::{bucket}/*"
    ivs_statements = [
        stmt
        for stmt in policy["Statement"]
        if "ivs" in str(stmt.get("Principal", {}).get("Service", "")).lower()
    ]
    assert ivs_statements, f"no ivs-principal statement in bucket policy: {policy['Statement']}"

    expected_principal = f"ivs-composite.{ctx.region}.amazonaws.com"
    for stmt in ivs_statements:
        assert stmt["Principal"]["Service"] == expected_principal, (
            f"expected principal {expected_principal!r}, got {stmt['Principal']['Service']!r}"
        )
        assert stmt["Effect"] == "Allow", f"expected Allow, got {stmt['Effect']!r}: {stmt}"
        assert stmt["Resource"] == bucket_objects_arn, (
            f"expected statement scoped to {bucket_objects_arn!r}, got {stmt['Resource']!r}"
        )
        actions = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
        assert "s3:PutObject" in actions, f"expected s3:PutObject among granted actions, got {actions}"
        secure_transport = stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        assert secure_transport == "true", (
            f"expected the grant to require aws:SecureTransport=true, got {secure_transport!r}: {stmt}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
