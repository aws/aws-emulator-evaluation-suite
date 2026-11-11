"""listener-certificate-empty-vs-absent-distinction."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "listener-certificate-empty-vs-absent-distinction"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After an add+remove certificate cycle, DescribeListenerCertificates returns the same list
    as an untouched sibling listener: just the default cert, with no leftover entry."""
    subnet_ids = _two_subnets(ctx)
    default_cert_arn = _import_self_signed_cert(ctx, "sim2real-behav-default")
    extra_cert_arn = _import_self_signed_cert(ctx, "sim2real-behav-extra")

    elbv2 = ctx.client("elbv2")
    lb_name = ctx.unique_name("sim2real-behav-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    fixed_response = {
        "Type": "fixed-response",
        "FixedResponseConfig": {"MessageBody": "ok", "StatusCode": "200", "ContentType": "text/plain"},
    }

    untouched_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": default_cert_arn}],
        DefaultActions=[fixed_response],
    )["Listeners"][0]["ListenerArn"]

    touched_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=8443,
        Certificates=[{"CertificateArn": default_cert_arn}],
        DefaultActions=[fixed_response],
    )["Listeners"][0]["ListenerArn"]
    elbv2.add_listener_certificates(
        ListenerArn=touched_listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )
    elbv2.remove_listener_certificates(
        ListenerArn=touched_listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )

    untouched_certs = elbv2.describe_listener_certificates(ListenerArn=untouched_listener_arn)[
        "Certificates"
    ]
    touched_certs = elbv2.describe_listener_certificates(ListenerArn=touched_listener_arn)[
        "Certificates"
    ]

    def _normalize(certs):
        return sorted((c["CertificateArn"], c["IsDefault"]) for c in certs)

    assert len(untouched_certs) == 1, f"expected exactly 1 certificate, got {untouched_certs!r}"
    assert untouched_certs[0]["CertificateArn"] == default_cert_arn, (
        f"expected default cert {default_cert_arn}, got {untouched_certs[0]['CertificateArn']}"
    )
    assert untouched_certs[0]["IsDefault"] is True, (
        f"expected IsDefault True for the default cert, got {untouched_certs[0]['IsDefault']!r}"
    )
    assert _normalize(touched_certs) == _normalize(untouched_certs), (
        f"listener with an add+remove cycle diverged from a never-touched listener: "
        f"{touched_certs!r} vs {untouched_certs!r}"
    )


# ===== helpers =====

def _two_subnets(ctx) -> list[str]:
    """Reuse a VPC with subnets in >=2 AZs if one exists, else create one.

    Always creating a VPC would exhaust the per-region VPC quota."""
    ec2 = ctx.client("ec2")
    reused = _find_reusable_subnets(ec2, ctx=ctx)
    if reused:
        return reused
    return _create_vpc_and_subnets(ctx)


def _find_reusable_subnets(ec2, *, ctx) -> list[str] | None:
    vpcs = sorted(ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"], key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]
    return None


def _create_vpc_and_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError("region does not have at least 2 available availability zones")

    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_name = ctx.unique_name("sim2real-behav-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _import_self_signed_cert(ctx, common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dns_name = f"{common_name}.example.com"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": ctx.unique_name(f"{common_name}-")}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_while_held(lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceInUseException", timeout_s=600.0))
    return cert_arn


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
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
