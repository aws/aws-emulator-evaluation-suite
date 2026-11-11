"""delete-trust-store-in-use-rejected."""
from __future__ import annotations

import datetime
import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-trust-store-in-use-rejected"
GROUP = "e2e"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrustStore on a trust store associated with a listener fails with TrustStoreInUse and the exact message
    and keeps it; once the association is removed the same delete succeeds and the store is TrustStoreNotFound."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    _key, _cert, ca_cert_pem, _key_pem = _generate_ca()
    server_cert_pem, server_key_pem = _generate_server_cert()

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_cert_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="ca-bundle.pem"))

    ts_arn = elbv2.create_trust_store(
        Name=ctx.unique_name("sim2real-ts-")[:32].rstrip("-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_trust_store_safe(elbv2, ts_arn))
    _wait_trust_store_status(elbv2, ts_arn, "ACTIVE", timeout_s=120)

    cert_arn = acm.import_certificate(
        Certificate=server_cert_pem,
        PrivateKey=server_key_pem,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    net = _create_network(ctx, ec2)
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-"),
        Protocol="HTTPS",
        Port=443,
        VpcId=net["vpc_id"],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-elbv2-")[:32].rstrip("-"),
        Subnets=net["subnet_ids"],
        SecurityGroups=[net["sg_id"]],
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    _wait_lb_active(elbv2, lb_arn, timeout_s=180)

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )["Listeners"][0]["ListenerArn"]
    # DescribeTrustStoreAssociations reports the association against the load balancer's ARN,
    # not the listener's: a listener ARN never appears here.
    _wait_association(elbv2, ts_arn, lb_arn, want_present=True, timeout_s=180)

    code, message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    assert code == "TrustStoreInUse", f"expected TrustStoreInUse, got code={code!r}"
    assert message == f"Trust store with ARN '{ts_arn}' is currently associated", f"delete_trust_store MESSAGE={message!r}"

    still_there = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert still_there and still_there[0]["TrustStoreArn"] == ts_arn, (
        "trust store must still exist after a rejected delete"
    )

    # Positive control: once the association is removed, the same delete call succeeds.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    _wait_association(elbv2, ts_arn, lb_arn, want_present=False, timeout_s=180)
    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    code2, message2 = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code2 == "TrustStoreNotFound", f"expected TrustStoreNotFound, got code={code2!r}"
    assert message2 == f"Trust store ARN '{ts_arn}' not found", f"describe_trust_stores MESSAGE={message2!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _generate_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, cert, cert_pem, key_pem


def _generate_server_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2.example.com")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("sim2real-elbv2.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-elbv2-ts2-").lower().replace("_", "-").rstrip("-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _delete_trust_store_safe(elbv2, ts_arn: str, attempts: int = 12, delay: float = 5.0) -> None:
    for _ in range(attempts):
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
            return
        except elbv2.exceptions.TrustStoreNotFoundException:
            return
        except elbv2.exceptions.TrustStoreInUseException:
            time.sleep(delay)


def _wait_trust_store_status(elbv2, ts_arn: str, want: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"]
        if status == want:
            return
        time.sleep(5)
    raise AssertionError(f"trust store never reached status={want}, last={status}")


def _wait_association(elbv2, ts_arn: str, resource_arn: str, want_present: bool, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    arns: list[str] = []
    while time.monotonic() < deadline:
        assocs = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
        arns = [a["ResourceArn"] for a in assocs]
        if (resource_arn in arns) == want_present:
            return
        time.sleep(5)
    raise AssertionError(f"n={len(arns)} got_type={(arns[0].split(':')[-1].split('/')[0] if arns else None)!r} want_type={resource_arn.split(':')[-1].split('/')[0]!r}")


def _tag_spec(resource_type: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "behavioral"}]}]


def _create_network(ctx, ec2) -> dict[str, Any]:
    vpc_id = ec2.create_vpc(CidrBlock="10.82.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones()["AvailabilityZones"]
        if z["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.82.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-elbv2-sg-"),
        Description="sim2real elbv2 trust store in-use behavioral check",
        TagSpecifications=_tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _retry_delete(fn, attempts: int = 24, delay: float = 5.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("DependencyViolation", "InvalidGroup.InUse", "InvalidVpcID.InUse", "ResourceInUse"):
                last = exc
                time.sleep(delay)
                continue
            raise
    if last:
        raise last


def _wait_lb_active(elbv2, lb_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(2)
    raise AssertionError(f"load balancer never became active, last state={state}")


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except elbv2.exceptions.LoadBalancerNotFoundException:
            return
        time.sleep(5)
    raise AssertionError("load balancer was not removed within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
