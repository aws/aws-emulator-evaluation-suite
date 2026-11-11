"""add-listener-certificate-nonexistent-arn-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "add-listener-certificate-nonexistent-arn-rejected"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates with a nonexistent certificate ARN fails with CertificateNotFound and the exact
    message and leaves only the default certificate, while adding a real certificate to the same listener succeeds."""
    subnet_ids = _two_subnets(ctx)
    default_cert_arn = _import_self_signed_cert(ctx, "sim2real-behav-default")
    real_extra_cert_arn = _import_self_signed_cert(ctx, "sim2real-behav-extra")

    elbv2 = ctx.client("elbv2")
    lb_name = ctx.unique_name("sim2real-behav-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": default_cert_arn}],
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "MessageBody": "ok",
                    "StatusCode": "200",
                    "ContentType": "text/plain",
                },
            }
        ],
    )["Listeners"][0]["ListenerArn"]

    # Syntactically ARN-shaped (same account/region/prefix) but referring to a certificate
    # ID that was never created.
    bogus_cert_arn = default_cert_arn[:-8] + "0" * 8

    code, message = _error_code(
        lambda: elbv2.add_listener_certificates(
            ListenerArn=listener_arn, Certificates=[{"CertificateArn": bogus_cert_arn}]
        )
    )
    assert code == "CertificateNotFound", f"CODE={code!r}"
    expected_message = f"Certificate '{bogus_cert_arn}' not found"
    assert message == expected_message, f"MESSAGE={message!r}"

    certs_after_rejection = elbv2.describe_listener_certificates(ListenerArn=listener_arn)[
        "Certificates"
    ]
    assert len(certs_after_rejection) == 1, (
        f"expected the rejected AddListenerCertificates call to leave no trace, got "
        f"{certs_after_rejection!r}"
    )
    assert certs_after_rejection[0]["CertificateArn"] == default_cert_arn

    elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": real_extra_cert_arn}]
    )
    certs_after_success = elbv2.describe_listener_certificates(ListenerArn=listener_arn)[
        "Certificates"
    ]
    assert {c["CertificateArn"] for c in certs_after_success} == {
        default_cert_arn,
        real_extra_cert_arn,
    }, f"positive control did not add the real certificate: {certs_after_success!r}"


# ===== helpers =====

def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected AddListenerCertificates to reject the bogus certificate ARN, but it "
        f"succeeded: {result!r}"
    )


def _two_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
            "Subnets"
        ]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    # No usable shared network (a freshly provisioned account may not have one) — create a
    # throwaway VPC + 2 subnets ourselves instead of depending on the ambient environment.
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")},
        ],
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.99.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        ec2.create_tags(
            Resources=[subnet_id], Tags=[{"Key": "sim2real:managed", "Value": "true"}]
        )
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


def _delete_certificate_when_released(acm, cert_arn: str, timeout_s: float = 300.0) -> None:
    """DeleteCertificate, retrying while the just-deleted load balancer still holds the cert.

    DeleteLoadBalancer returns before ACM drops the association, so ResourceInUseException is
    expected for a while; a not-found means the certificate is already gone.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
