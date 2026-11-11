"""describe-listener-certificates-not-found."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-listener-certificates-not-found"
GROUP = 'listener-errors'
SERVICES = ['elbv2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeListenerCertificates returns a real HTTPS listener's default certificate, and raises
    ListenerNotFoundException for a never-created listener ARN on the same load balancer."""
    subnet_ids = _two_subnets(ctx)
    acm = ctx.client("acm")
    cert_arn = _import_self_signed_cert(acm, "sim2real-behav-dlc")

    elbv2 = ctx.client("elbv2")
    lb_name = ctx.unique_name("sim2real-behav-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["LoadBalancers"][0]["LoadBalancerArn"]

    real_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
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

    def _cleanup():
        # ACM refuses to delete a certificate still attached to a listener, and detaching it
        # happens on DeleteListener, not on the (asynchronous) DeleteLoadBalancer -- so delete
        # the listener and wait out the detach before deleting the certificate, then the LB.
        try:
            elbv2.delete_listener(ListenerArn=real_listener_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ListenerNotFound":
                raise
        deadline = time.monotonic() + 30.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)

    ctx.on_cleanup(_cleanup)

    real_certs = elbv2.describe_listener_certificates(ListenerArn=real_listener_arn)[
        "Certificates"
    ]
    assert any(c["CertificateArn"] == cert_arn for c in real_certs), (
        f"positive control failed: DescribeListenerCertificates on the real listener did not "
        f"return the default certificate {cert_arn!r}: {real_certs!r}"
    )

    # Well-formed but never-created: same load balancer, a listener id that was never issued.
    bogus_arn = real_listener_arn[:-16] + "0123456789abcdef"

    code, message = _error(lambda: elbv2.describe_listener_certificates(ListenerArn=bogus_arn))
    assert code == "ListenerNotFound", f"expected ListenerNotFound, got {code!r}"
    assert message == "One or more listeners not found", f"describe_listener_certificates MESSAGE={message!r}"



def _error(fn):
    """Call fn(); return the botocore error (code, message). Raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _two_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no default VPC is available in this account/region to source subnets for an ALB"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "default VPC does not span at least 2 availability zones, required to create an ALB"
        )
    return list(by_az.values())[:2]


def _import_self_signed_cert(acm, common_name: str) -> str:
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
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    return resp["CertificateArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
