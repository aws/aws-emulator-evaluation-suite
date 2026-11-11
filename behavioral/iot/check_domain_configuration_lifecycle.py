"""domain-configuration-lifecycle."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CUSTOMER_MANAGED domain configuration whose validation certificate is self-signed is
    rejected with InvalidRequestException and never created, while an AWS-managed default succeeds;
    Describe then 404s and Delete on the never-created name succeeds.
    """
    iot = ctx.client("iot")
    acm = ctx.client("acm")

    name = ctx.unique_name("sim2real-domain-cfg-")
    domain_name = f"{name}.example.com"

    server_pem, server_key_pem = _generate_self_signed_cert(domain_name)
    server_cert_arn = acm.import_certificate(Certificate=server_pem, PrivateKey=server_key_pem)[
        "CertificateArn"
    ]
    ctx.on_cleanup(lambda: _delete_cert_quiet(acm, server_cert_arn))

    # The AWS-managed default is the only reachable positive control: a CUSTOMER_MANAGED config
    # needs a public-CA validation certificate. AWS-managed configs must stay DISABLED for 7 days
    # before deletion, so cleanup only disables this one.
    control_name = ctx.unique_name("sim2real-domain-cfg-control-")
    iot.create_domain_configuration(
        domainConfigurationName=control_name,
        serviceType="DATA",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _disable_domain_configuration_quiet(iot, control_name))
    control = iot.describe_domain_configuration(domainConfigurationName=control_name)
    assert control["domainConfigurationName"] == control_name, (
        f"expected positive control {control_name!r}, got {control.get('domainConfigurationName')!r}"
    )
    assert control["domainConfigurationStatus"] == "ENABLED", (
        f"expected positive control ENABLED, got {control.get('domainConfigurationStatus')!r}"
    )

    validation_pem, validation_key_pem = _generate_self_signed_cert(domain_name)
    validation_cert_arn = acm.import_certificate(
        Certificate=validation_pem, PrivateKey=validation_key_pem
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_quiet(acm, validation_cert_arn))

    # The validation certificate is self-signed, not issued by a public CA, so AWS IoT cannot use
    # it to prove ownership of domain_name.
    code, message = _error_code_and_message(
        lambda: iot.create_domain_configuration(
            domainConfigurationName=name,
            domainName=domain_name,
            serverCertificateArns=[server_cert_arn],
            validationCertificateArn=validation_cert_arn,
            serviceType="DATA",
        )
    )
    assert code == "InvalidRequestException", f"unexpected code: {code!r} message={message!r}"
    expected_message = "Validation certificate must be signed by trusted CA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    code, message = _error_code_and_message(
        lambda: iot.describe_domain_configuration(domainConfigurationName=name)
    )
    assert code == "ResourceNotFoundException", f"expected the rejected config to be absent, got {code!r}"
    expected_absent = (
        "Could not find domain configuration for given account ID and domain configuration name, "
        f"AccountId: {ctx.account}, DomainConfigurationName: {name}"
    )
    assert message == expected_absent, f"expected message {expected_absent!r}, got {message!r}"

    # Unlike Describe, DeleteDomainConfiguration succeeds silently on a never-created name.
    iot.delete_domain_configuration(domainConfigurationName=name)


def _error_code_and_message(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), or raise if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _delete_cert_quiet(acm, cert_arn):
    try:
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _disable_domain_configuration_quiet(iot, name):
    try:
        iot.update_domain_configuration(domainConfigurationName=name, domainConfigurationStatus="DISABLED")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # Best-effort: an AWS-managed domain configuration cannot be deleted until it has been
    # DISABLED for 7 days, so this fails right after creation.
    try:
        iot.delete_domain_configuration(domainConfigurationName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
