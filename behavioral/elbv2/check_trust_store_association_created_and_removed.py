"""trust-store-association-created-and-removed."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "trust-store-association-created-and-removed"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a trust store with a listener lists the load balancer in DescribeTrustStoreAssociations, a
    same-account DeleteSharedTrustStoreAssociation fails with the exact message, and detaching clears the entry."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    cert_arn = _import_acm_cert(ctx, "sim2real-mtls.example.com", lb_arn)

    ts_arn = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-"))

    listener_arn = _create_https_listener(
        ctx,
        lb_arn,
        tg_arn,
        cert_arn,
        mutual_authentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )

    # Real AWS reports the trust store association at the load balancer level (ResourceArn is the
    # load balancer ARN), not per-listener.
    associations = _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60,
        interval_s=3,
    )
    assert any(a["ResourceArn"] == lb_arn for a in associations), (
        f"load balancer association missing: {associations}"
    )

    # Real AWS only allows DeleteSharedTrustStoreAssociation for cross-account (shared) associations;
    # a same-account association must be rejected with this specific error (wire code has no
    # "Exception" suffix).
    code, message = _error(
        lambda: elbv2.delete_shared_trust_store_association(TrustStoreArn=ts_arn, ResourceArn=listener_arn)
    )
    assert code == "DeleteAssociationSameAccount", f"expected same-account rejection, got {code}"
    expected_message = (
        f"Cannot remove the association because the trust store ARN '{ts_arn}' and resource ARN "
        f"'{listener_arn}' belong to the same account"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Disassociate the trust store the supported way: turn mutual auth off on the listener.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})

    associations_after = _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: not any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60,
        interval_s=3,
    )
    assert not any(a["ResourceArn"] == lb_arn for a in associations_after), (
        f"association still present after detaching mutual auth: {associations_after}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


# One deadline shared by all of the check's teardowns, inside the suite's 900 s cleanup budget.
_TEARDOWN_S = 840.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    import time as _time

    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, _time.monotonic() + _TEARDOWN_S)
    return held[1]


def _safe_call(ctx, fn) -> None:
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s to the shared deadline, anything else raises."""
    from botocore.exceptions import ClientError

    deadline = _deadline(ctx)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _default_vpc_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:2]
    return _create_own_vpc_two_subnets(ctx)


def _create_own_vpc_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: _delete_net(ctx, ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(
        Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}]
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError("region does not have >=2 available AZs")
    subnet_ids = []
    for i in range(2):
        az = azs[i]["ZoneName"]
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az)[
            "Subnet"
        ]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _safe_call(ctx, lambda: _delete_net(ctx, ec2, "delete_subnet", SubnetId=subnet_id)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


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
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: _delete_net(ctx, ec2, "delete_security_group", GroupId=sg_id)))
    return sg_id


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-tg-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
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


def _import_acm_cert(ctx, cn: str, lb_arn: str) -> str:
    key_pem, cert_pem = _self_signed_cert(cn)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    arn = resp["CertificateArn"]
    elbv2 = ctx.client("elbv2")

    def _cleanup() -> None:
        # The listener holds the certificate until its load balancer is gone, so that goes first.
        _delete_lb_and_wait(ctx, elbv2, lb_arn)
        _safe_call(ctx, lambda: acm.delete_certificate(CertificateArn=arn))

    ctx.on_cleanup(_cleanup)
    return arn


def _delete_lb_and_wait(ctx, elbv2, lb_arn: str) -> None:
    """DeleteLoadBalancer, then poll every 2 s until DescribeLoadBalancers no longer resolves the ARN."""
    import time as _time

    from botocore.exceptions import ClientError

    _safe_call(ctx, lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    deadline = _deadline(ctx)
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        if _time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still resolves at the teardown deadline")
        _time.sleep(2)


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
    return resp["Listeners"][0]["ListenerArn"]


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
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ts_arn


# Subnet / security group / VPC deletes fail with DependencyViolation while AWS-managed ENIs of an
# asynchronously deleted resource (e.g. a load balancer) remain, so wait (bounded) for them to go,
# retry inside one shared window, and finally raise naming the ENIs still attached.
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(ctx, client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = _deadline(ctx)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
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
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
