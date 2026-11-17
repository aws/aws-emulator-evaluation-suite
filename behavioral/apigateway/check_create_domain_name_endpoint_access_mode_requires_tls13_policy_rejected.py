"""create-domain-name-endpoint-access-mode-requires-tls13-policy-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-name-endpoint-access-mode-requires-tls13-policy-rejected"
GROUP = "custom-domains"
SERVICES = ["apigateway", "acm"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _self_signed_cert_arn(ctx, common_name: str) -> str:
    """Import a throwaway self-signed certificate into ACM and return its ARN."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    acm = ctx.client("acm")
    imported = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_once_released(acm, cert_arn))
    return cert_arn


def _delete_cert_once_released(acm, cert_arn: str, budget_s: float = 240.0) -> None:
    """DeleteCertificate, retrying only ResourceInUseException while API Gateway still
    references the certificate right after its domain name is deleted."""
    import time as _time

    deadline = _time.monotonic() + budget_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or _time.monotonic() > deadline:
                raise
            _time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainName rejects endpointAccessMode on a domain whose securityPolicy is not one
    of the SecurityPolicy_* policies, while the identical endpointAccessMode succeeds once the
    domain's securityPolicy is such a policy."""
    apigw = ctx.client("apigateway")

    control_domain = (ctx.unique_name("sim2real-eam-ok-") + ".example.com").lower()
    control_cert_arn = _self_signed_cert_arn(ctx, control_domain)

    control = apigw.create_domain_name(
        domainName=control_domain,
        regionalCertificateArn=control_cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=control_domain))
    assert control["securityPolicy"] == "TLS_1_2", (
        f"positive control: expected securityPolicy 'TLS_1_2', got {control['securityPolicy']!r}"
    )
    assert "endpointAccessMode" not in control or control["endpointAccessMode"] is None, (
        f"positive control: expected no endpointAccessMode, got {control.get('endpointAccessMode')!r}"
    )

    rejected_domain = (ctx.unique_name("sim2real-eam-bad-") + ".example.com").lower()
    rejected_cert_arn = _self_signed_cert_arn(ctx, rejected_domain)
    code, message = _error(lambda: apigw.create_domain_name(
        domainName=rejected_domain,
        regionalCertificateArn=rejected_cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
        endpointAccessMode="STRICT",
        tags={"sim2real": CHECK},
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException for endpointAccessMode with securityPolicy TLS_1_2, got {code!r}"
    )
    expected_message = "Endpoint access mode is not supported for this security policy"
    assert message == expected_message, f"unexpected BadRequestException message {message!r}"

    not_found_code, not_found_message = _error(
        lambda: apigw.get_domain_name(domainName=rejected_domain)
    )
    assert not_found_code == "NotFoundException", (
        f"expected the rejected domain to not exist, got {not_found_code!r} reading it"
    )
    assert not_found_message == "Invalid domain name identifier specified", (
        f"unexpected not-found message {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
