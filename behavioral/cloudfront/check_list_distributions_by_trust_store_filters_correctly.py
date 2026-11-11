"""list-distributions-by-trust-store-filters-correctly."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-trust-store-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByTrustStore returns an empty DistributionList for a real, unreferenced
    trust store and EntityNotFound once that trust store is deleted (GetTrustStore agrees)."""
    ca_pem = _generate_self_signed_ca_pem()

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = _create_bucket(ctx)
    key = "sim2real-trust-store-ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=ca_pem)

    name = ctx.unique_name("sim2real-truststore-")
    create_resp = cf.create_trust_store(
        Name=name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": key, "Region": ctx.region}
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    trust_store_id = create_resp["TrustStore"]["Id"]

    state = {"deleted": False}

    def _cleanup_trust_store() -> None:
        if state["deleted"]:
            return
        try:
            etag = cf.get_trust_store(Identifier=trust_store_id)["ETag"]
            cf.delete_trust_store(Id=trust_store_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup_trust_store)

    empty = cf.list_distributions_by_trust_store(TrustStoreIdentifier=trust_store_id)
    quantity = empty["DistributionList"]["Quantity"]
    assert quantity == 0, f"expected an unassociated trust store to report Quantity=0, got {quantity!r}"
    items = empty["DistributionList"].get("Items", [])
    assert items == [], f"expected an unassociated trust store to report no Items, got {items!r}"

    etag = cf.get_trust_store(Identifier=trust_store_id)["ETag"]
    cf.delete_trust_store(Id=trust_store_id, IfMatch=etag)
    state["deleted"] = True

    code, message = _error_code_and_message(
        lambda: cf.list_distributions_by_trust_store(TrustStoreIdentifier=trust_store_id)
    )
    assert code == "EntityNotFound", f"expected EntityNotFound from list-by-trust-store on a deleted id, got {code!r}"
    assert message == "The specified trust store does not exist.", f"unexpected message {message!r}"

    get_code, get_message = _error_code_and_message(lambda: cf.get_trust_store(Identifier=trust_store_id))
    assert get_code == "EntityNotFound", f"expected EntityNotFound from GetTrustStore on a deleted id, got {get_code!r}"
    assert get_message == "The specified trust store does not exist.", f"unexpected message {get_message!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_ca_pem() -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-trust-store-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ts-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
