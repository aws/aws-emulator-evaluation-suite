"""trust-store-association-lifecycle-via-mtls-listener."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-association-lifecycle-via-mtls-listener"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling mTLS on an HTTPS listener via ModifyListener makes DescribeTrustStoreAssociations
    list the load balancer ARN; after mTLS is turned off the association clears, and once deleted
    the trust store fails with TrustStoreNotFound."""
    import cryptography  # noqa: F401

    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _default_vpc_two_az_subnets(ctx)
    ts_arn = _create_trust_store(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)
    tg_arn = _create_target_group(ctx, vpc_id)
    cert_arn = _import_self_signed_cert(ctx, "sim2real-elbv2-mtls-default")

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    before = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert lb_arn not in {a["ResourceArn"] for a in before}, (
        f"load balancer {lb_arn} already associated with trust store {ts_arn} before mTLS was "
        f"configured: {before}"
    )

    # mTLS is set through ModifyListener; ModifyListenerAttributes carries no trust-store keys.
    elbv2.modify_listener(
        ListenerArn=listener_arn, MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn}
    )

    # Associations are keyed by the load balancer ARN, not the listener ARN, even though
    # MutualAuthentication is configured per listener.
    associations = _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: lb_arn in {a["ResourceArn"] for a in assocs},
        timeout_s=120,
        interval_s=5,
    )
    assert lb_arn in {a["ResourceArn"] for a in associations}, (
        f"load balancer {lb_arn} never appeared in DescribeTrustStoreAssociations for trust store "
        f"{ts_arn} after ModifyListener enabled mTLS: {associations}"
    )

    described = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    mtls = described["MutualAuthentication"]
    assert mtls["Mode"] == "verify", f"expected MutualAuthentication.Mode='verify', got {mtls!r}"
    assert mtls["TrustStoreArn"] == ts_arn, (
        f"expected MutualAuthentication.TrustStoreArn={ts_arn!r}, got {mtls!r}"
    )

    # Turning mTLS off clears the association only eventually; DeleteTrustStore before that
    # fails with ResourceInUse, so wait for it here rather than in the short cleanup window.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: lb_arn not in {a["ResourceArn"] for a in assocs},
        timeout_s=90,
        interval_s=3,
    )
    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    code, message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound after delete, got {code!r}"
    expected_message = f"Trust store ARN '{ts_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====


def _free_trust_store_quota(ctx, prefix: str = "sim2real-ts") -> None:
    """Best-effort delete leftover trust stores with this prefix, as the per-account quota is low.
    Waits for each deletion to take effect, because a deleting store still counts against it."""
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
        # A store still associated with a load balancer cannot be deleted (ResourceInUse);
        # deleting the load balancer removes its listeners and releases the association.
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
        # Load balancer deletion takes minutes and the association persists until it finishes,
        # so wait well past typical deletion latency before deleting the trust store.
        lb_gone_deadline = time.monotonic() + 300.0
        for lb_arn in lb_arns:
            while time.monotonic() < lb_gone_deadline:
                try:
                    elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
                except Exception:
                    break
                time.sleep(5)
        deleted = False
        delete_deadline = time.monotonic() + 120.0
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


def _create_trust_store_retrying(ctx, elbv2, name: str, bucket: str, key: str) -> dict:
    """CreateTrustStore, retrying TooManyTrustStores for up to 10 minutes, because concurrent
    checks share the quota and freeing a slot can wait on load balancer deletion."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600.0
    while True:
        try:
            return elbv2.create_trust_store(
                Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key
            )["TrustStores"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] != "TooManyTrustStores" or time.monotonic() >= deadline:
                raise
            _free_trust_store_quota(ctx)
            time.sleep(5)


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _default_vpc_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 availability zones")
    subnet_ids = list(by_az.values())[:2]
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lb-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _cleanup():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code in ("active", "active_impaired"),
        timeout_s=180,
        interval_s=5,
    )
    return arn


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")[:32]
    tg = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")[
        "TargetGroups"
    ][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, arn))
    elbv2.add_tags(ResourceArns=[arn], Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    return arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-assoc").lower().replace("_", "-")
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


def _self_signed_ca_cert_and_key(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _self_signed_leaf_cert_and_key(common_name: str):
    """A self-signed CA:FALSE server certificate with a SAN for the listener; ELB rejects a
    CA:TRUE listener certificate with UnsupportedCertificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _create_trust_store(ctx) -> str:

    elbv2 = ctx.client("elbv2")
    _free_trust_store_quota(ctx)
    bucket = _create_bucket(ctx)
    cert_pem, _ = _self_signed_ca_cert_and_key("sim2real-elbv2-assoc-ca")
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    name = ctx.unique_name("sim2real-ts-assoc-")[:32]
    ts_arn = _create_trust_store_retrying(ctx, elbv2, name, bucket, "ca-bundle.pem")["TrustStoreArn"]
    elbv2.add_tags(ResourceArns=[ts_arn], Tags=[{"Key": "sim2real:managed", "Value": "true"}])

    def _cleanup():
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrustStoreNotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    return ts_arn


def _import_self_signed_cert(ctx, common_name: str) -> str:
    acm = ctx.client("acm")
    cert_pem, key_pem = _self_signed_leaf_cert_and_key(common_name)
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["CertificateArn"]

    def _cleanup():
        from botocore.exceptions import ClientError

        # The listener is deleted first (LIFO), but it releases the certificate only eventually,
        # so DeleteCertificate can briefly fail with ResourceInUseException.
        deadline = time.monotonic() + 120.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return arn


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
