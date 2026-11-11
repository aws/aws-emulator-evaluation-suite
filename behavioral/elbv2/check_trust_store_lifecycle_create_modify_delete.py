"""trust-store-lifecycle-create-modify-delete."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-lifecycle-create-modify-delete"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateTrustStore reaches ACTIVE; ModifyTrustStore swaps the CA bundle; after DeleteTrustStore,
    DescribeTrustStores and ModifyTrustStore fail with TrustStoreNotFound and the exact message."""
    import cryptography  # noqa: F401

    elbv2 = ctx.client("elbv2")
    _free_trust_store_quota(ctx)
    bucket = _create_bucket(ctx)

    ca1_pem, _, _, ca1_cert = _self_signed_cert_and_key(ctx, "sim2real-elbv2-ts-ca-1")
    ca2_pem, _, _, ca2_cert = _self_signed_cert_and_key(ctx, "sim2real-elbv2-ts-ca-2")
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="bundle-1.pem", Body=ca1_pem)
    s3.put_object(Bucket=bucket, Key="bundle-2.pem", Body=ca2_pem)

    name = ctx.unique_name("sim2real-ts-")[:32]
    ts_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]
    created = _create_trust_store_retrying(ctx, elbv2, name, bucket, "bundle-1.pem", ts_tags)
    ts_arn = created["TrustStoreArn"]

    def _cleanup_ts():
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrustStoreNotFound":
                raise

    ctx.on_cleanup(_cleanup_ts)

    status1 = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda ts: ts["Status"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert status1["Status"] == "ACTIVE"
    assert status1["NumberOfCaCertificates"] == 1
    assert status1["Name"] == name

    # Modify the bundle: content must actually change, not just the API call succeeding.
    elbv2.modify_trust_store(
        TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="bundle-2.pem"
    )
    status2 = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda ts: ts["Status"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert status2["Status"] == "ACTIVE"
    assert status2["NumberOfCaCertificates"] == 1

    # Prove the bundle in effect is bundle-2, not bundle-1: fetch it back and compare CN.
    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    fetched = _fetch_uri(ctx, location)
    from cryptography import x509

    fetched_cert = x509.load_pem_x509_certificate(fetched)
    assert fetched_cert.subject == ca2_cert.subject
    assert fetched_cert.subject != ca1_cert.subject

    elbv2.delete_trust_store(TrustStoreArn=ts_arn)

    # ELBv2's wire error code for this modeled exception omits the "Exception" suffix that
    # botocore's generated exception class name (TrustStoreNotFoundException) carries.
    code, message = _client_error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound, got {code}"
    expected = f"Trust store ARN '{ts_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Gone means unusable, not just unlisted: a mutation on the dead id must fail the same way.
    modify_code, modify_message = _client_error(
        lambda: elbv2.modify_trust_store(
            TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="bundle-1.pem"
        )
    )
    assert modify_code == "TrustStoreNotFound", f"expected TrustStoreNotFound on dead id, got {modify_code}"
    expected = f"Trust store ARN '{ts_arn}' not found"
    assert modify_message == expected, f"expected message {expected!r}, got {modify_message!r}"


def _free_trust_store_quota(ctx, prefix: str = "sim2real-ts") -> None:
    """Trust stores are a scarce, account-wide quota (real AWS enforces a low ceiling via
    TooManyTrustStoresException). Prior runs of these checks can leave test trust stores
    behind (e.g. an interrupted run whose cleanup did not execute); best-effort delete any
    leftover trust stores from this test suite before creating a new one so CreateTrustStore
    does not spuriously fail with TooManyTrustStores. DeleteTrustStore is itself asynchronous
    on real AWS: a trust store that was just told to delete keeps counting against the quota
    for a short window afterwards, so this also waits (bounded) for each deletion to actually
    take effect before returning -- otherwise the CreateTrustStore call that immediately
    follows can still observe TooManyTrustStoresException."""
    elbv2 = ctx.client("elbv2")
    stores = []
    marker = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        try:
            resp = elbv2.describe_trust_stores(**kwargs)
        except Exception:
            return
        stores.extend(resp.get("TrustStores", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    for ts in stores:
        if not ts.get("Name", "").startswith(prefix):
            continue
        arn = ts["TrustStoreArn"]
        # A leftover trust store from an interrupted prior run can still be associated
        # with a load balancer (e.g. via a listener's MutualAuthentication config). Such a
        # trust store cannot be deleted (ResourceInUseException) and would otherwise
        # permanently occupy a slot in the account-wide trust store quota forever. Tear
        # down any associated load balancers first (best-effort; deleting a load balancer
        # implicitly deletes its listeners, releasing the association) so the delete below
        # actually succeeds instead of being silently swallowed.
        try:
            assocs = elbv2.describe_trust_store_associations(TrustStoreArn=arn)["TrustStoreAssociations"]
        except Exception:
            assocs = []
        lb_arns = [a.get("ResourceArn") for a in assocs if a.get("ResourceArn")]
        for lb_arn in lb_arns:
            try:
                elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            except Exception:
                pass
        # DeleteLoadBalancer only *requests* teardown; on real AWS deleting an ALB/NLB takes
        # on the order of minutes, and the trust store association (and thus
        # DeleteTrustStore's ResourceInUseException) does not clear until the load balancer
        # has actually finished disappearing. Wait for each associated load balancer to
        # actually go away before attempting the trust store delete, instead of retrying
        # DeleteTrustStore in a tight loop that gives up long before the load balancer
        # teardown can possibly have finished. The bound here is kept inside the check's own
        # suite timeout budget (300s total for the whole check) rather than spanning the
        # full LB-teardown latency: a bound long enough to cover that latency would itself
        # guarantee this check gets killed by the harness with no diagnostic whenever this
        # rare recovery path actually triggers, which is strictly worse than a fast, clear
        # AssertionError from the caller. A leftover load balancer that outlives this window
        # is a pre-existing account problem, not something this check can absorb.
        lb_gone_deadline = time.monotonic() + 90.0
        for lb_arn in lb_arns:
            while time.monotonic() < lb_gone_deadline:
                try:
                    elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
                except Exception:
                    break
                time.sleep(5)
        deleted = False
        delete_deadline = time.monotonic() + 60.0
        while time.monotonic() < delete_deadline:
            try:
                elbv2.delete_trust_store(TrustStoreArn=arn)
                deleted = True
                break
            except Exception:
                time.sleep(5)
        if not deleted:
            continue
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                elbv2.describe_trust_stores(TrustStoreArns=[arn])
            except Exception:
                break
            time.sleep(3)


def _create_trust_store_retrying(ctx, elbv2, name: str, bucket: str, key: str, ts_tags: list) -> dict:
    """CreateTrustStore can still hit TooManyTrustStoresException right after
    _free_trust_store_quota ran, because other checks in this same suite concurrently create
    and delete their own trust stores against the same account-wide quota, and because
    freeing a quota slot occupied by a leftover trust store that is still associated with a
    load balancer can itself take several minutes (see _free_trust_store_quota). Retry on
    that specific error instead of treating a transient quota clash as a hard failure, but
    bounded well inside the check's own suite timeout budget (a bound spanning the full
    load-balancer-teardown latency would itself guarantee a silent harness timeout with no
    diagnostic, which is worse than a clear AssertionError here)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return elbv2.create_trust_store(
                Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key, Tags=ts_tags
            )["TrustStores"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] != "TooManyTrustStores" or time.monotonic() >= deadline:
                raise
            _free_trust_store_quota(ctx)
            time.sleep(5)


def _client_error(fn) -> tuple[str, str]:
    """Call fn and return the (Code, Message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-ts").lower().replace("_", "-")
    # us-east-1 is a genuine S3 API quirk, not a region pin: passing a LocationConstraint for
    # us-east-1 itself raises InvalidLocationConstraint, so the literal only ever selects the
    # no-argument form of the same create_bucket call ctx.region would otherwise drive.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _self_signed_cert_and_key(ctx, common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, key, cert


def _fetch_uri(ctx, uri: str) -> bytes:
    if uri.startswith("s3://"):
        rest = uri[len("s3://") :]
        bucket, _, key = rest.partition("/")
        s3 = ctx.client("s3")
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    import urllib.request

    _url, _route = ctx.endpoint_route(uri)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310
        return resp.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
