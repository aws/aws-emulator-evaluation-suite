"""e2e-trust-store-mtls-association-and-revocation-flow."""
from __future__ import annotations

import datetime
import time
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trust-store-mtls-association-and-revocation-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A trust store associates to an HTTPS listener's mutual auth, a revocation round-trips through S3,
    a same-account DeleteSharedTrustStoreAssociation is rejected with the association intact, and
    detaching then deleting removes the listener's dependency on the trust store."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    acm = ctx.client("acm")

    bucket = _create_bucket(ctx)

    ca_key = _gen_key()
    ca_cert = _self_signed_cert(ca_key, "sim2real-mtls-ca", is_ca=True)
    ca_bundle_pem = _pem_cert(ca_cert)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_bundle_pem)

    ts_name = _short_name("sim2realts")
    trust_store = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]
    ts_arn = trust_store["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _wait_for_trust_store_active(ctx, ts_arn)

    server_key = _gen_key()
    server_cert = _self_signed_cert(server_key, "sim2real.example.invalid")
    cert_arn = acm.import_certificate(
        Certificate=_pem_cert(server_cert),
        PrivateKey=_pem_key(server_key),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_certificate(CertificateArn=cert_arn)))

    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)
    lb_name = _short_name("sim2real-mtls")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _wait_for_lb_active(ctx, lb_arn)

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    # DescribeTrustStoreAssociations reports the owning load balancer's ARN (not the
    # listener ARN) as the associated resource for an ALB listener's mTLS trust store.
    deadline = time.monotonic() + 60.0
    associations: list = []
    while time.monotonic() < deadline:
        associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
        if any(a["ResourceArn"] == lb_arn for a in associations):
            break
        time.sleep(3.0)
    assert any(a["ResourceArn"] == lb_arn for a in associations), (
        f"load balancer {lb_arn} not found in trust store associations {associations}"
    )

    revoked_serial = x509.random_serial_number()
    crl_pem = _build_crl(ca_key, ca_cert, revoked_serial)
    s3.put_object(Bucket=bucket, Key="revoked.pem", Body=crl_pem)

    revocation = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"RevocationType": "CRL", "S3Bucket": bucket, "S3Key": "revoked.pem"}],
    )["TrustStoreRevocations"][0]
    revocation_id = revocation["RevocationId"]

    content = elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=revocation_id)
    _url, _route = ctx.endpoint_route(content["Location"])
    fetched = urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=20).read()
    assert fetched == crl_pem, "content fetched from the presigned revocation Location did not match the uploaded CRL"

    # Same-account association deletion must be rejected: DeleteSharedTrustStoreAssociation is
    # only for cross-account (RAM-shared) associations, and the effect (association) must persist.
    code, message = _expect_rejected(
        lambda: elbv2.delete_shared_trust_store_association(TrustStoreArn=ts_arn, ResourceArn=lb_arn)
    )
    assert code == "DeleteAssociationSameAccount", (
        f"expected DeleteAssociationSameAccount when deleting a same-account association, got {code!r}"
    )
    expected_message = (
        f"Cannot remove the association because the trust store ARN '{ts_arn}' and resource ARN "
        f"'{lb_arn}' belong to the same account"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    associations_after = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert any(a["ResourceArn"] == lb_arn for a in associations_after), (
        "association was removed despite the rejected DeleteSharedTrustStoreAssociation call"
    )

    # Positive control: the documented way to detach same-account mTLS is ModifyListener.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    deadline = time.monotonic() + 60.0
    detached = False
    while time.monotonic() < deadline:
        remaining = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
        if not any(a["ResourceArn"] == lb_arn for a in remaining):
            detached = True
            break
        time.sleep(3.0)
    assert detached, "listener still associated with the trust store after ModifyListener Mode=off"

    elbv2.delete_listener(ListenerArn=listener_arn)
    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    deadline = time.monotonic() + 60.0
    ts_gone = False
    while time.monotonic() < deadline:
        try:
            code, _message = _expect_rejected(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
        except AssertionError:
            code = None
        if code == "TrustStoreNotFound":
            ts_gone = True
            break
        time.sleep(3.0)
    assert ts_gone, "trust store was still describable after DeleteTrustStore"


# ===== helpers =====


def _short_name(prefix: str, max_len: int = 32) -> str:
    suffix = uuid.uuid4().hex[:10]
    name = f"{prefix}-{suffix}"
    return name[:max_len].rstrip("-")


def _expect_rejected(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ListenerNotFound",
            "LoadBalancerNotFound",
            "ResourceNotFoundException",
            "TrustStoreNotFound",
        ):
            raise


def _create_vpc_and_subnets(ctx, num_subnets: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:num_subnets]
    ]
    if len(azs) < num_subnets:
        raise AssertionError(f"region exposes only {len(azs)} available AZ(s); need {num_subnets} for an ALB")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_net(ec2, vpc_id, f"subnet {sid}", lambda: ec2.delete_subnet(SubnetId=sid))
        )
    return vpc_id, subnet_ids


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        last_state = lb["State"]["Code"]
        if last_state == "active":
            return
        if last_state == "failed":
            raise AssertionError(f"load balancer {lb_arn} entered failed state")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never became active (last state={last_state})")


def _wait_for_trust_store_active(ctx, ts_arn: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        last_status = ts["Status"]
        if last_status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store never became ACTIVE (last status={last_status})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = _short_name("sim2real-mtls", max_len=63)
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _self_signed_cert(key, cn: str, is_ca: bool = False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    return builder.sign(key, hashes.SHA256())


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _build_crl(ca_key, ca_cert, revoked_serial: int) -> bytes:
    now = datetime.datetime.utcnow()
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_serial)
        .revocation_date(now)
        .build()
    )
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


# Check-created VPC networking is torn down only once the AWS-managed ENIs inside it are gone.
# Holder here: the internal Application Load Balancer (its per-subnet ENIs drain for
# a minute or more after DeleteLoadBalancer returns).
# It deletes ASYNCHRONOUSLY: the delete call returns while its requester-managed ENIs still sit in
# the VPC, and a DeleteSecurityGroup / DeleteSubnet / DeleteVpc issued in that window fails with
# DependencyViolation. So every network delete waits (bounded) for the VPC to hold no ENIs, retries
# DependencyViolation within the same window, and raises a final failure naming what still holds
# the VPC. The window is shared by all of one VPC's network deletes and the holder cleanups before it.
_NET_TEARDOWN_S = 840.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(15)
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{label}: {code}; ENIs still in {vpc_id}: {_vpc_enis(ec2, vpc_id)}"
                ) from exc
        time.sleep(15)


def _vpc_enis(ec2, vpc_id) -> list:
    try:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [
        f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
        for e in enis["NetworkInterfaces"]
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
