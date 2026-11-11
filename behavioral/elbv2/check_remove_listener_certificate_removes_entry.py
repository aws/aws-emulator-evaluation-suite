"""remove-listener-certificate-removes-entry."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remove-listener-certificate-removes-entry"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveListenerCertificates removes a non-default certificate from the listener's list."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids, sg_id = _create_vpc_and_subnets(ctx)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, [sg_id])

    default_cert_arn = _import_self_signed_certificate(ctx, ctx.unique_name("elbv2-default-"))
    listener_arn = _create_https_listener(ctx, lb_arn, default_cert_arn, tg_arn)

    extra_cert_arn = _import_self_signed_certificate(ctx, ctx.unique_name("elbv2-extra-"))
    elbv2.add_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}])

    before_certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    before = {c["CertificateArn"] for c in before_certs}
    assert before == {default_cert_arn, extra_cert_arn}, (
        f"expected default+extra cert attached before removal, got {before}"
    )

    elbv2.remove_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}])

    after_certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    after = {c["CertificateArn"] for c in after_certs}
    assert after == {default_cert_arn}, f"expected only default cert to remain after removal, got {after}"
    assert extra_cert_arn not in after, f"removed cert {extra_cert_arn} still present in {after}"

    survivor = next(c for c in after_certs if c["CertificateArn"] == default_cert_arn)
    assert survivor.get("IsDefault") is True, (
        f"surviving cert after removal should be reported as the default, got IsDefault={survivor.get('IsDefault')!r}"
    )


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

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _find_reusable_vpc(ec2, *, ctx):
    """Reuse an existing VPC that already has subnets spanning >=2 AZs and a default security
    group, instead of always provisioning a fresh one. This check has no need for a dedicated
    VPC, but always creating one can exhaust the account's per-region VPC quota when many
    behavioral checks run back-to-back (VpcLimitExceeded)."""
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


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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
