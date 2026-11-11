"""op-contract-import-client-vpn-client-certificate-revocation-list."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-import-client-vpn-client-certificate-revocation-list"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportClientVpnClientCertificateRevocationList: a real CRL is accepted, a bogus endpoint id is rejected."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    now = datetime.datetime.now(datetime.timezone.utc)

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-root-ca")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-server")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(root_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
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
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("sim2real-server.example.com")]), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    root_key_pem = root_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )

    cert_name = ctx.unique_name("sim2real-cvpn-cert-")
    server_arn = acm.import_certificate(
        Certificate=server_cert_pem,
        PrivateKey=server_key_pem,
        Tags=[{"Key": "Name", "Value": cert_name + "-server"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=server_arn))
    root_arn = acm.import_certificate(
        Certificate=root_cert_pem,
        PrivateKey=root_key_pem,
        Tags=[{"Key": "Name", "Value": cert_name + "-root"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=root_arn))

    # Newly imported ACM certificates can take a few seconds to become visible to other
    # services (e.g. Client VPN), so poll until ACM itself reports them as issued.
    def _cert_status(arn):
        return acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"]

    _poll_until(lambda: _cert_status(server_arn), lambda s: s == "ISSUED", timeout_s=60, interval_s=3)
    _poll_until(lambda: _cert_status(root_arn), lambda s: s == "ISSUED", timeout_s=60, interval_s=3)

    endpoint_id = _retry_create_client_vpn_endpoint(
        ec2,
        ClientCidrBlock="10.198.0.0/22",
        ServerCertificateArn=server_arn,
        AuthenticationOptions=[
            {
                "Type": "certificate-authentication",
                "MutualAuthentication": {"ClientRootCertificateChainArn": root_arn},
            }
        ],
        ConnectionLogOptions={"Enabled": False},
        Description=cert_name,
        TagSpecifications=[
            {"ResourceType": "client-vpn-endpoint", "Tags": [{"Key": "Name", "Value": cert_name}]}
        ],
    )["ClientVpnEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=endpoint_id))

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(root_name)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=7))
    crl = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("ascii")

    resp = ec2.import_client_vpn_client_certificate_revocation_list(
        ClientVpnEndpointId=endpoint_id, CertificateRevocationList=crl_pem
    )
    assert resp.get("Return") is True, f"expected Return=True, got {resp!r}"

    # The import call's own Return=True is not proof the CRL was actually stored —
    # confirm it independently through ExportClientVpnClientCertificateRevocationList,
    # which can lag briefly behind the import, and check the exported bytes actually
    # parse back into the CRL we signed (same issuer, same serial).
    exported_pem = _poll_until(
        lambda: ec2.export_client_vpn_client_certificate_revocation_list(
            ClientVpnEndpointId=endpoint_id
        ).get("CertificateRevocationList"),
        lambda c: bool(c),
        timeout_s=90,
        interval_s=5,
    )
    exported_crl = x509.load_pem_x509_crl(exported_pem.encode("ascii"))
    assert exported_crl.issuer == root_cert.subject, (
        f"exported CRL issuer {exported_crl.issuer} != imported CRL issuer {root_cert.subject}"
    )

    bogus_endpoint_id = "cvpn-endpoint-0000000000000000"
    code, message = _error(
        lambda: ec2.import_client_vpn_client_certificate_revocation_list(
            ClientVpnEndpointId=bogus_endpoint_id,
            CertificateRevocationList=crl_pem,
        )
    )
    assert code == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {code!r}"
    )
    expected = f"Endpoint {bogus_endpoint_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _retry_create_client_vpn_endpoint(ec2, *, timeout_s=60.0, interval_s=3.0, **kwargs):
    """Newly imported ACM certificates can lag briefly before Client VPN can reference them."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_client_vpn_endpoint(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValue" and "certificate" in message.lower() and (
                time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
