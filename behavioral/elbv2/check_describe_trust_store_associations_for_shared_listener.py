"""describe-trust-store-associations-for-shared-listener."""
from __future__ import annotations

import datetime
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-trust-store-associations-for-shared-listener"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trust store has no associations until an mTLS verify listener uses it; then the listener
    reports it and DescribeTrustStoreAssociations lists it with the load balancer ARN as resource."""
    elbv2 = ctx.client("elbv2")

    # Overall budget under the 300s per-check limit; the association poll gets whatever setup leaves.
    _run_deadline = time.monotonic() + 260.0

    def _setup_trust_store():
        bucket = _create_bucket(ctx)
        ca_pem, _key, _cert = _self_signed_ca(ctx.unique_name("elbv2-ca-"))
        _put_object(ctx, bucket, "ca-bundle.pem", ca_pem)
        arn = elbv2.create_trust_store(
            Name=_ts_name(ctx), CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
        )["TrustStores"][0]["TrustStoreArn"]
        ctx.on_cleanup(lambda: _retry_while_held(lambda: elbv2.delete_trust_store(TrustStoreArn=arn), "TrustStoreInUse", timeout_s=600.0))
        _wait_for_trust_store_status(ctx, arn, "ACTIVE")
        return arn

    def _setup_load_balancer():
        vpc_id, subnet_ids, sg_id = _create_vpc_and_subnets(ctx)
        tg_arn = _create_target_group(ctx, vpc_id)
        lb_arn = _create_alb(ctx, subnet_ids, [sg_id])
        cert_arn = _import_self_signed_certificate(ctx, ctx.unique_name("elbv2-leaf-"))
        return tg_arn, lb_arn, cert_arn

    # CA-bundle validation and ALB provisioning can each take over a minute; overlap them so
    # setup costs the slower of the two rather than their sum.
    ts_arn, (tg_arn, lb_arn, cert_arn) = _run_concurrently(_setup_trust_store, _setup_load_balancer)

    # before any listener is attached, there are no associations
    initial = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert initial == [], f"expected no associations before any listener attaches the trust store, got {initial}"

    listener_arn = _create_https_listener(
        ctx, lb_arn, cert_arn, tg_arn,
        mutual_authentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )

    listener = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    mtls = listener["MutualAuthentication"]
    assert mtls["Mode"] == "verify", f"expected MutualAuthentication.Mode='verify', got {mtls.get('Mode')!r}"
    assert mtls["TrustStoreArn"] == ts_arn, (
        f"expected MutualAuthentication.TrustStoreArn={ts_arn!r}, got {mtls.get('TrustStoreArn')!r}"
    )

    # The association can take well over 90s to appear. It is reported at the load balancer
    # level, so its ResourceArn is the load balancer ARN, not the listener ARN.
    _remaining = max(30.0, _run_deadline - time.monotonic())
    associations = _poll_for_association(ctx, elbv2, ts_arn, lb_arn, timeout_s=_remaining)
    assert len(associations) == 1, f"expected exactly one association for {ts_arn}, got {associations}"
    assert associations[0]["ResourceArn"] == lb_arn, (
        f"expected the association's ResourceArn to be the load balancer {lb_arn!r}, "
        f"got {associations[0]['ResourceArn']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2ts-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 rejects a LocationConstraint; every other region requires one.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str, body: bytes) -> None:
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _ts_name(ctx) -> str:
    return ctx.unique_name("ts-")[:32].rstrip("-")


def _self_signed_ca(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key, cert


def _wait_for_trust_store_status(ctx, arn: str, target_status: str, timeout_s: float = 150.0, interval_s: float = 3.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
        last = ts["Status"]
        if last == target_status:
            return ts
        time.sleep(interval_s)
    raise AssertionError(f"trust store {arn} did not reach {target_status} within {timeout_s}s (last={last})")


def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource_type}-")}],
    }


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    reused = _find_reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(CidrBlock="10.88.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.88.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _find_reusable_vpc(ec2, *, ctx):
    """Reuse an existing VPC with subnets in >=2 AZs and a default security group, so the
    per-region VPC quota (VpcLimitExceeded) is not exhausted."""
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    except ClientError:
        return None
    vpcs = sorted(vpcs, key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) < 2:
            continue
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        if not sgs:
            continue
        return vpc_id, list(by_az.values())[:2], sgs[0]["GroupId"]
    return None


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_ids) -> str:
    elbv2 = ctx.client("elbv2")
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=sg_ids,
        Scheme="internal", Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_for_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return lb
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State'].get('Reason')}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer did not reach active within {timeout_s}s")


def _import_self_signed_certificate(ctx, common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_while_held(lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceInUseException", timeout_s=600.0))
    return cert_arn


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise


def _create_https_listener(ctx, lb_arn, cert_arn, tg_arn, mutual_authentication=None, port=443) -> str:
    elbv2 = ctx.client("elbv2")
    kwargs = dict(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=port,
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    if mutual_authentication:
        kwargs["MutualAuthentication"] = mutual_authentication
    listener_arn = elbv2.create_listener(**kwargs)["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    return listener_arn


def _run_concurrently(*fns):
    """Run zero-arg callables on threads and return their results in call order.

    A worker's exception is re-raised only after all threads finish, so every setup registers cleanup."""
    results: list = [None] * len(fns)
    errors: list = [None] * len(fns)

    def _runner(i, fn):
        try:
            results[i] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the calling thread below
            errors[i] = exc

    threads = [threading.Thread(target=_runner, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for exc in errors:
        if exc is not None:
            raise exc
    return results


def _poll_for_association(ctx, elbv2, ts_arn: str, resource_arn: str, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Poll DescribeTrustStoreAssociations until it lists resource_arn; the association is created
    asynchronously after CreateListener returns."""
    deadline = time.monotonic() + timeout_s
    associations = []
    while time.monotonic() < deadline:
        associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
        if any(a["ResourceArn"] == resource_arn for a in associations):
            return associations
        time.sleep(interval_s)
    raise AssertionError(
        f"trust store {ts_arn} did not show an association with {resource_arn} within "
        f"{timeout_s}s (last seen: {associations})"
    )


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

