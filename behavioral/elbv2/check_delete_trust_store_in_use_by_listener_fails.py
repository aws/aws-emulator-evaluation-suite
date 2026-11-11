"""delete-trust-store-in-use-by-listener-fails."""
from __future__ import annotations

import concurrent.futures
import re
import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-trust-store-in-use-by-listener-fails"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrustStore on a trust store associated with a verify-mode mTLS listener fails with TrustStoreInUse and
    the exact message and keeps it; with mutual authentication off, the delete succeeds and the store is gone."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids, sg_id = _create_network(ctx)

    # Trust-store provisioning (S3 bucket+object, CreateTrustStore, wait-for-ACTIVE) and
    # load-balancer/target-group/certificate provisioning are independent async operations --
    # nothing below needs one before the other, only CreateListener afterward needs all of their
    # results. Running them concurrently keeps the trust store's own (up to ~120s) ACTIVE wait off
    # the critical path, leaving as much of the shared 300s per-check budget as possible for the
    # (unavoidably serial, listener-must-exist-first) association wait that follows CreateListener.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        ts_fut = pool.submit(_create_active_trust_store, ctx)
        lb_fut = pool.submit(_create_alb, ctx, subnet_ids, sg_id)
        tg_fut = pool.submit(_create_target_group, ctx, vpc_id)
        cert_fut = pool.submit(_import_self_signed_cert, ctx, "sim2real-inuse")
    # Registered after every worker has finished, so it runs first: the target group and
    # certificate stay in use until the load balancer (and the listener on it) is gone.
    if lb_fut.exception() is None:
        ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_fut.result()))
    ts_arn = ts_fut.result()
    lb_arn = lb_fut.result()
    tg_arn = tg_fut.result()
    cert_arn = cert_fut.result()

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )["Listeners"][0]["ListenerArn"]
    # DescribeTrustStoreAssociations reports the association's ResourceArn as the LOAD BALANCER
    # ARN, not the listener ARN, even though MutualAuthentication is configured per-listener
    # (the DeleteSharedTrustStoreAssociation example also takes a `loadbalancer/...` ResourceArn).
    _wait_association(ctx, ts_arn, lb_arn)

    code, message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    # ELBv2's wire error code for this modeled exception omits the "Exception" suffix
    # that botocore's generated exception class name carries.
    assert code == "TrustStoreInUse", f"expected TrustStoreInUse, got {code}"
    assert message == f"Trust store with ARN '{ts_arn}' is currently associated", f"delete_trust_store MESSAGE={message!r}"

    still_exists = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert len(still_exists) == 1 and still_exists[0]["TrustStoreArn"] == ts_arn, (
        f"trust store {ts_arn} must still exist after a rejected delete, got {still_exists!r}"
    )

    # Positive control: removing the precondition (the mTLS association) unlocks deletion.
    # DeleteTrustStore is retried on TrustStoreInUse: the association listing and the trust store's
    # deletability do not clear in lockstep, and the delete succeeds as soon as the in-use lock clears.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    _delete_trust_store_once_unblocked(ctx, ts_arn)
    not_found_code, not_found_message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert not_found_code == "TrustStoreNotFound", (
        f"expected TrustStoreNotFound after successful delete, got {not_found_code}"
    )
    assert not_found_message == f"Trust store ARN '{ts_arn}' not found", f"describe_trust_stores MESSAGE={not_found_message!r}"


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-inuse"}]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "", raw)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    cleaned = cleaned[:32].rstrip("-")
    return cleaned or "sim2real-fallback"


def _retry_delete(fn, retry_codes: tuple[str, ...], attempts: int = 24, delay: float = 5.0) -> None:
    # DeleteLoadBalancer only requests teardown, so a target group or certificate a listener used
    # briefly stays in use after it returns: retry the delete on those transient conflict codes.
    from botocore.exceptions import ClientError

    last: ClientError | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in retry_codes:
                raise
            last = exc
            time.sleep(delay)
    if last:
        raise last


_VPC_DEPENDENCY_CODES = ("DependencyViolation", "InvalidGroup.InUse", "InvalidVpcID.InUse")
_RESOURCE_IN_USE_CODES = ("ResourceInUse", "ResourceInUseException")


def _create_network(ctx: Any):
    # Never depend on an ambient default VPC: a freshly provisioned account may not have one,
    # so this check creates and tears down its own VPC and two subnets in distinct AZs instead.
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_kv()}
    ])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), _VPC_DEPENDENCY_CODES))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones()["AvailabilityZones"]
        if z["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"fewer than 2 available AZs in {ctx.region}, got {azs!r}")
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid), _VPC_DEPENDENCY_CODES))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=_safe_name(ctx, "sim2real-sg-"),
        Description="sim2real elbv2 trust-store-in-use behavioral check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id), _VPC_DEPENDENCY_CODES))
    return vpc_id, subnet_ids, sg_id


def _create_alb(ctx: Any, subnet_ids, sg_id: str) -> str:
    # CreateListener/ModifyListener (and so the trust-store<->listener association) does not need
    # the load balancer to be "active": the listener attaches to the LoadBalancerArn CreateLoadBalancer
    # returns, so only the association's own bounded poll is on the critical path.
    elbv2 = ctx.client("elbv2")
    name = _safe_name(ctx, "sim2real-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Type="application",
        Scheme="internal",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]["LoadBalancerArn"]
    return lb_arn


def _delete_lb_and_wait(elbv2: Any, lb_arn: str, timeout_s: float = 240.0) -> None:
    """DeleteLoadBalancer, then poll every 2 s until DescribeLoadBalancers reports
    LoadBalancerNotFound; raises if it still resolves at the deadline."""
    from botocore.exceptions import ClientError

    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still resolves {timeout_s}s after delete")
        time.sleep(2)


def _create_target_group(ctx: Any, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = _safe_name(ctx, "sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance", Tags=_tags_kv()
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn),
            _RESOURCE_IN_USE_CODES,
            attempts=90,
            delay=2.0,
        )
    )
    return tg_arn


def _self_signed_leaf_pem(common_name: str):
    import datetime

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
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _import_self_signed_cert(ctx: Any, common_name: str) -> str:
    cert_pem, key_pem = _self_signed_leaf_pem(common_name)
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, Tags=_tags_kv())["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: acm.delete_certificate(CertificateArn=cert_arn),
            _RESOURCE_IN_USE_CODES,
            attempts=90,
            delay=2.0,
        )
    )
    return cert_arn


def _self_signed_ca_pem(common_name: str):
    import datetime

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
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = _safe_name(ctx, "sim2real-elbv2-inuse-")
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" itself (it is the
    # implicit default region for the call) -- this is the bucket's own region, not an
    # assumption about where the rest of the check runs.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _put_object(ctx: Any, bucket: str, key: str, body: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))


def _create_active_trust_store(ctx: Any) -> str:
    ca_pem = _self_signed_ca_pem("sim2real-inuse-ca")
    bucket = _create_bucket(ctx)
    _put_object(ctx, bucket, "bundle.pem", ca_pem)
    elbv2 = ctx.client("elbv2")
    ts_name = _safe_name(ctx, "tstore-inuse-")
    ts_arn = _create_trust_store_with_capacity(
        ctx,
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="bundle.pem",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_trust_store_if_present(elbv2, ts_arn))
    _wait_trust_store_active(ctx, ts_arn)
    return ts_arn


def _reclaim_stale_trust_stores(ctx: Any) -> None:
    """Best-effort cleanup of leftover test trust stores (named with our own tstore- prefix)
    that are blocking CreateTrustStore because the account's TooManyTrustStores quota is
    shared with other trust-store checks in this batch and prior runs may have leaked
    trust stores (e.g. a run interrupted before its on_cleanup ran)."""
    import time as _t

    from botocore.exceptions import ClientError

    elbv2 = ctx.client("elbv2")
    try:
        stores = elbv2.describe_trust_stores()["TrustStores"]
    except ClientError:
        return
    for s in stores:
        arn = s.get("TrustStoreArn")
        if not arn or not str(s.get("Name", "")).startswith("tstore-"):
            continue
        try:
            assocs = elbv2.describe_trust_store_associations(TrustStoreArn=arn)[
                "TrustStoreAssociations"
            ]
        except ClientError:
            assocs = []
        for a in assocs:
            try:
                elbv2.modify_listener(
                    ListenerArn=a["ResourceArn"], MutualAuthentication={"Mode": "off"}
                )
            except ClientError:
                pass
        if assocs:
            deadline = _t.monotonic() + 30.0
            while _t.monotonic() < deadline:
                try:
                    remaining = elbv2.describe_trust_store_associations(TrustStoreArn=arn)[
                        "TrustStoreAssociations"
                    ]
                except ClientError:
                    break
                if not remaining:
                    break
                _t.sleep(3.0)
        try:
            elbv2.delete_trust_store(TrustStoreArn=arn)
        except ClientError:
            pass


def _create_trust_store_with_capacity(ctx: Any, **kwargs) -> str:
    """create_trust_store, reclaiming quota from leaked test trust stores and retrying once
    if the account-wide TooManyTrustStores quota is currently exhausted."""
    from botocore.exceptions import ClientError

    elbv2 = ctx.client("elbv2")
    try:
        return elbv2.create_trust_store(**kwargs)["TrustStores"][0]["TrustStoreArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TooManyTrustStores":
            raise
        _reclaim_stale_trust_stores(ctx)
        return elbv2.create_trust_store(**kwargs)["TrustStores"][0]["TrustStoreArn"]


def _wait_trust_store_active(ctx: Any, ts_arn: str, timeout_s: float = 120.0, interval_s: float = 5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        if last["Status"] == "ACTIVE":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"trust store never reached ACTIVE, last status={last}")


def _wait_association(ctx: Any, ts_arn: str, resource_arn: str, timeout_s: float = 240.0, interval_s: float = 5.0):
    # The trust-store<->load-balancer association propagates asynchronously to the underlying
    # nodes (independently of, and roughly concurrently with, the load balancer's own
    # provisioning), so a bounded poll (rather than assuming it is immediate) is required here.
    # `resource_arn` must be the LOAD BALANCER ARN, not the listener ARN: DescribeTrustStoreAssociations
    # reports associations keyed by the load balancer even though MutualAuthentication is configured
    # per-listener (the DeleteSharedTrustStoreAssociation example takes a `loadbalancer/...` ResourceArn).
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        assocs = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)[
            "TrustStoreAssociations"
        ]
        for a in assocs:
            if a["ResourceArn"] == resource_arn:
                return a
        time.sleep(interval_s)
    raise AssertionError(f"resource {resource_arn} never appeared in trust store associations")


def _delete_trust_store_if_present(elbv2: Any, ts_arn: str) -> None:
    """Teardown: the check body deletes the trust store itself, so not-found here is the expected end state."""
    from botocore.exceptions import ClientError

    try:
        elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _delete_trust_store_once_unblocked(ctx: Any, ts_arn: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    """Retry DeleteTrustStore, catching TrustStoreInUse, until it succeeds or the ceiling fires."""
    from botocore.exceptions import ClientError

    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrustStoreInUse":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"trust store {ts_arn} still TrustStoreInUse after disassociation"
                ) from exc
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
