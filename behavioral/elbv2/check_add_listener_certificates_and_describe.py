"""add-listener-certificates-and-describe."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-listener-certificates-and-describe"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Certificates added via AddListenerCertificates are returned by DescribeListenerCertificates."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids, sg_id = _create_vpc_and_subnets(ctx)
    # Imported before the load balancer exists so their teardowns run after it is gone: ACM
    # refuses DeleteCertificate while a listener still uses the certificate.
    default_cert_arn = _import_self_signed_certificate(ctx, ctx.unique_name("elbv2-default-"), teardown_deadline)
    extra_cert_arn = _import_self_signed_certificate(ctx, ctx.unique_name("elbv2-extra-"), teardown_deadline)
    tg_arn = _create_target_group(ctx, vpc_id, teardown_deadline)
    lb_arn = _create_alb(ctx, subnet_ids, [sg_id], teardown_deadline)

    listener_arn = _create_https_listener(ctx, lb_arn, default_cert_arn, tg_arn)

    before = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    before_arns = {c["CertificateArn"] for c in before}
    assert before_arns == {default_cert_arn}, (
        f"expected only the default cert {default_cert_arn} before any AddListenerCertificates "
        f"call, got {before_arns}"
    )

    added = elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )["Certificates"]
    added_arns = {c["CertificateArn"] for c in added}
    assert extra_cert_arn in added_arns, (
        f"expected {extra_cert_arn} in AddListenerCertificates response, got {added_arns}"
    )

    described = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    by_arn = {c["CertificateArn"]: c for c in described}
    assert set(by_arn) == {default_cert_arn, extra_cert_arn}, (
        f"expected DescribeListenerCertificates to return exactly "
        f"{{{default_cert_arn}, {extra_cert_arn}}}, got {set(by_arn)}"
    )
    assert by_arn[default_cert_arn]["IsDefault"] is True, (
        f"expected the original cert {default_cert_arn} to remain IsDefault=True, "
        f"got {by_arn[default_cert_arn]['IsDefault']!r}"
    )
    assert by_arn[extra_cert_arn]["IsDefault"] is False, (
        f"expected the cert added via AddListenerCertificates {extra_cert_arn} to be "
        f"IsDefault=False, got {by_arn[extra_cert_arn]['IsDefault']!r}"
    )


# ===== helpers =====

def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource_type}-")}],
    }


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_target_group(ctx, vpc_id: str, teardown_deadline) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_in_use(
        ctx, lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn), "ResourceInUse", "TargetGroupNotFound",
        teardown_deadline))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_ids, teardown_deadline) -> str:
    elbv2 = ctx.client("elbv2")
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=sg_ids,
        Scheme="internal", Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(ctx, elbv2, lb_arn, teardown_deadline))
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


def _import_self_signed_certificate(ctx, common_name: str, teardown_deadline) -> str:
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
    ctx.on_cleanup(lambda: _retry_in_use(
        ctx, lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceInUseException",
        "ResourceNotFoundException", teardown_deadline))
    return cert_arn


#: One window per run for the load balancer, target group and certificate teardowns; with the
#: network window below it stays inside the suite's 900 s cleanup budget.
_LB_TEARDOWN_S = 240.0


def _lb_deadline(teardown_deadline) -> float:
    """The run's load balancer teardown deadline, opened by its first teardown call."""
    return teardown_deadline.setdefault("t", time.monotonic() + _LB_TEARDOWN_S)


def _retry_in_use(ctx, fn, in_use: str, gone: str, teardown_deadline) -> None:
    """One teardown call, retried every 2 s while `in_use` refuses it; `gone` means done."""
    deadline = _lb_deadline(teardown_deadline)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone:
                return
            if code != in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_lb_and_wait(ctx, elbv2, lb_arn: str, teardown_deadline) -> None:
    """DeleteLoadBalancer, then poll every 2 s until DescribeLoadBalancers reports it gone."""
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = _lb_deadline(teardown_deadline)
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still resolves {_LB_TEARDOWN_S}s after delete")
        time.sleep(2)


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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
