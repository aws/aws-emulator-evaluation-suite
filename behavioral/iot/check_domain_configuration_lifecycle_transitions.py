"""domain-configuration-lifecycle-transitions."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-configuration-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CUSTOMER_MANAGED CreateDomainConfiguration with a self-signed server certificate and no
    validationCertificateArn is rejected, and the configuration is absent from Describe and List.
    """
    iot = ctx.client("iot")
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-iot-domcfg-")
    domain_name = f"{name}.example.com".lower()

    server_cert_pem, server_key_pem = _generate_self_signed_cert(domain_name)

    server_cert_arn = acm.import_certificate(
        Certificate=server_cert_pem.encode(), PrivateKey=server_key_pem.encode()
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=server_cert_arn))

    # A full ENABLED -> DISABLED -> DELETE lifecycle needs a publicly trusted certificate for an
    # owned domain; the certificate here is self-signed with no validationCertificateArn.
    code, message = _error_code_and_message(
        lambda: iot.create_domain_configuration(
            domainConfigurationName=name,
            domainName=domain_name,
            serverCertificateArns=[server_cert_arn],
            serviceType="DATA",
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}: {message}"
    expected_message = (
        "Must provide validation certificate when using server certificates not signed by "
        "trusted CA or not within"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the domain configuration was never created.
    described_code, described_message = _error_code_and_message(
        lambda: iot.describe_domain_configuration(domainConfigurationName=name)
    )
    assert described_code == "ResourceNotFoundException", (
        f"expected DescribeDomainConfiguration to report ResourceNotFoundException for a "
        f"configuration that was never created, got {described_code!r}"
    )
    expected_absent = (
        "Could not find domain configuration for given account ID and domain configuration name, "
        f"AccountId: {ctx.account}, DomainConfigurationName: {name}"
    )
    assert described_message == expected_absent, (
        f"expected message {expected_absent!r}, got {described_message!r}"
    )

    listed_names = [
        d["domainConfigurationName"]
        for d in iot.list_domain_configurations().get("domainConfigurations", [])
    ]
    assert name not in listed_names, (
        f"expected {name!r} absent from ListDomainConfigurations since creation was rejected, "
        f"but it is present: {listed_names}"
    )

    # Deleting a never-created configuration is an idempotent success on real AWS.
    iot.delete_domain_configuration(domainConfigurationName=name)


def _error_code_and_message(fn):
    """Call fn(); return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_cert(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
