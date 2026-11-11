"""delete-trust-store-in-use-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "delete-trust-store-in-use-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrustStore on a trust store attached to a listener fails with TrustStoreInUse and the exact message and
    keeps it; after detaching, the same delete succeeds and the store is TrustStoreNotFound."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    cert_arn = _import_acm_cert(ctx, "sim2real-mtls.example.com")
    ts_arn = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-"))

    listener_arn = _create_https_listener(
        ctx, lb_arn, tg_arn, cert_arn, mutual_authentication={"Mode": "verify", "TrustStoreArn": ts_arn}
    )

    code, message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    # Real AWS raises this error as "TrustStoreInUse" (no "Exception" suffix on the wire code).
    assert code == "TrustStoreInUse", f"expected TrustStoreInUse, got {code}"
    assert message == f"Trust store with ARN '{ts_arn}' is currently associated", f"delete_trust_store MESSAGE={message!r}"

    described = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert len(described) == 1, "trust store should still exist after the rejected delete"

    # Restore: detach the trust store from the listener. DeleteTrustStore then succeeds, but not
    # instantly — real AWS keeps rejecting with TrustStoreInUse for a few seconds after the
    # detachment even once describe_trust_store_associations already reports no association, so the
    # identical delete call is retried on that specific code rather than issued once.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    _retry_delete_until_it_succeeds(elbv2, ts_arn, timeout_s=180.0, interval_s=5.0)
    not_found_code, not_found_message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert not_found_code == "TrustStoreNotFound", f"expected TrustStoreNotFound, got {not_found_code}"
    assert not_found_message == f"Trust store ARN '{ts_arn}' not found", f"describe_trust_stores MESSAGE={not_found_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(fn, retry=(), gone=(), timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    """Run a teardown call. Codes in `gone` mean the resource is already deleted; codes in
    `retry` mean a dependent is still being torn down. Anything else, or a timeout, raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_lb_and_wait(elbv2, lb_arn: str) -> None:
    _teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), gone=("LoadBalancerNotFound",))
    elbv2.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_delete_until_it_succeeds(elbv2, ts_arn: str, timeout_s: float, interval_s: float) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
            return
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            if last_code != "TrustStoreInUse":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"delete_trust_store still failing {timeout_s}s after detaching the listener, last code={last_code}"
    )


def _default_vpc_two_subnets(ctx):
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
        raise AssertionError("shared network does not have subnets in >=2 AZs")
    return vpc_id, list(by_az.values())[:2]


def _new_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-elbv2-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: ec2.delete_security_group(GroupId=sg_id),
            retry=("DependencyViolation",),
            gone=("InvalidGroup.NotFound",),
            timeout_s=900.0,
        )
    )
    return sg_id


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-tg-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn),
            retry=("ResourceInUse",),
            gone=("TargetGroupNotFound",),
            timeout_s=600.0,
        )
    )
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    waiter = elbv2.get_waiter("load_balancer_available")
    waiter.wait(LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return lb_arn


def _self_signed_cert(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _import_acm_cert(ctx, cn: str) -> str:
    key_pem, cert_pem = _self_signed_cert(cn)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: acm.delete_certificate(CertificateArn=arn),
            retry=("ResourceInUseException",),
            gone=("ResourceNotFoundException",),
        )
    )
    return arn


def _create_https_listener(ctx, lb_arn, tg_arn, cert_arn, mutual_authentication=None):
    elbv2 = ctx.client("elbv2")
    kwargs = dict(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    if mutual_authentication:
        kwargs["MutualAuthentication"] = mutual_authentication
    resp = elbv2.create_listener(**kwargs)
    listener_arn = resp["Listeners"][0]["ListenerArn"]
    # Deleting the listener first releases the certificate and the trust store it holds.
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: elbv2.delete_listener(ListenerArn=listener_arn), gone=("ListenerNotFound",)
        )
    )
    return listener_arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=bucket)
    objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
    objects += [
        {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
    ]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_trust_store(ctx, cn: str) -> str:
    _key_pem, cert_pem = _self_signed_cert(cn)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
    )
    ts_arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn),
            retry=("TrustStoreInUse",),
            gone=("TrustStoreNotFound",),
        )
    )
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ts_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
