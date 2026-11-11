"""listener-certificate-add-describe-remove-lifecycle."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "listener-certificate-add-describe-remove-lifecycle"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates adds a cert visible via Describe; RemoveListenerCertificates removes it."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)

    default_cert_arn = _import_acm_cert(ctx, "sim2real-default.example.com", lb_arn)
    listener_arn = _create_https_listener(ctx, lb_arn, tg_arn, default_cert_arn)

    initial_certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    initial_arns = {c["CertificateArn"] for c in initial_certs}
    assert initial_arns == {default_cert_arn}, f"listener should start with only the default cert: {initial_arns}"

    extra_cert_arn = _import_acm_cert(ctx, "sim2real-extra.example.com", lb_arn)
    add_resp = elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )
    assert any(c["CertificateArn"] == extra_cert_arn for c in add_resp["Certificates"]), (
        f"AddListenerCertificates response missing the new cert: {add_resp['Certificates']}"
    )

    certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    arns = {c["CertificateArn"] for c in certs}
    assert extra_cert_arn in arns, f"added cert missing from DescribeListenerCertificates: {arns}"
    assert default_cert_arn in arns, f"default cert dropped from DescribeListenerCertificates after add: {arns}"
    extra_entry = next(c for c in certs if c["CertificateArn"] == extra_cert_arn)
    assert extra_entry.get("IsDefault") is False, f"newly added cert should not be default: {extra_entry}"

    elbv2.remove_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )
    certs_after = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    arns_after = {c["CertificateArn"] for c in certs_after}
    assert extra_cert_arn not in arns_after, "removed cert still present after RemoveListenerCertificates"
    assert default_cert_arn in arns_after, f"default cert missing from DescribeListenerCertificates after remove: {arns_after}"


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: _delete_net(ctx, ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region has fewer than 2 available AZs: {azs}")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_name = ctx.unique_name("sim2real-elbv2-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_call(ctx, lambda: _delete_net(ctx, ec2, "delete_subnet", SubnetId=sid)))
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
    resp = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": name}],
    )
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application",
        Tags=[{"Key": "Name", "Value": name}],
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
    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-cert-")}],
    )
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
    import time
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


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
