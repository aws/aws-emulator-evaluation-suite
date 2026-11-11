"""list-distributions-by-trust-store-index-consistency."""
from __future__ import annotations

import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-trust-store-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_TAGS = {"Items": [{"Key": "sim2real:managed", "Value": "true"}]}


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _generate_self_signed_ca_pem() -> bytes:
    with tempfile.TemporaryDirectory() as d:
        key_path = f"{d}/ca-key.pem"
        cert_path = f"{d}/ca-cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-days", "1", "-subj", "/CN=sim2real-cloudfront-trust-store-test-ca",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            return f.read()


def _create_ca_bundle_bucket_and_object(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-ts-").lower().replace("_", "-")
    key = "ca-bundle.pem"
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket, key))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key=key, Body=_generate_self_signed_ca_pem())
    return bucket, key


def _delete_bucket(ctx, bucket, key):
    s3 = ctx.client("s3")
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_trust_store(ctx, bucket, key):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-ts-")
    resp = cf.create_trust_store(
        Name=name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {
                "Bucket": bucket,
                "Key": key,
                "Region": ctx.region,
            }
        },
        Tags=_TAGS,
    )
    trust_store_id = resp["TrustStore"]["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(ctx, trust_store_id))
    return trust_store_id


def _delete_trust_store(ctx, trust_store_id):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_trust_store(Identifier=trust_store_id),
        lambda r: r["TrustStore"]["Status"] in ("active", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    cf.delete_trust_store(Id=trust_store_id, IfMatch=resp["ETag"])


def _list_distribution_ids_by_trust_store(cf, trust_store_id):
    ids = set()
    marker = None
    while True:
        kwargs = {"TrustStoreIdentifier": trust_store_id, "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_trust_store(**kwargs)
        dlist = resp["DistributionList"]
        ids.update(item["Id"] for item in dlist.get("Items", []))
        marker = dlist.get("NextMarker")
        if not marker:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore ingests a self-signed CA bundle from S3 (Status active, one CA certificate),
    and ListDistributionsByTrustStore reports no distributions for the unassociated trust store."""
    require_tools("openssl")

    cf = ctx.client("cloudfront")
    bucket, key = _create_ca_bundle_bucket_and_object(ctx)
    trust_store_id = _create_trust_store(ctx, bucket, key)

    deployed = _poll_until(
        lambda: cf.get_trust_store(Identifier=trust_store_id)["TrustStore"],
        lambda ts: ts["Status"] in ("active", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert deployed["Status"] == "active", (
        f"expected the self-signed CA bundle to be ingested successfully, got status "
        f"{deployed['Status']!r} (reason={deployed.get('Reason')!r})"
    )
    assert deployed["NumberOfCaCertificates"] == 1, (
        f"expected exactly 1 CA certificate ingested from the uploaded bundle, got "
        f"{deployed['NumberOfCaCertificates']!r}"
    )

    associated_ids = _list_distribution_ids_by_trust_store(cf, trust_store_id)
    assert associated_ids == set(), (
        f"a freshly created, unassociated trust store must have no associated "
        f"distributions, got {associated_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
