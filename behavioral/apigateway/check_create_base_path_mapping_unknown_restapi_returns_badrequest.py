"""create-base-path-mapping-unknown-restapi-returns-badrequest."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "create-base-path-mapping-unknown-restapi-returns-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBasePathMapping with a nonexistent restApiId returns BadRequestException and creates
    no mapping; mapping the same real custom domain to a deployed REST API succeeds."""

    domain = ctx.unique_name("sim2real-bpmdom-") + ".example.com"

    # The certificate's CN/SAN must match the domain name, or CreateDomainName itself is
    # rejected as "not covered by the provided certificate".
    cert_pem, key_pem = _self_signed_cert(domain)

    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    imported = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))

    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))

    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain, restApiId="nonexist12", basePath="bad"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid REST API identifier specified", f"unexpected BadRequestException message {message!r}"

    mappings = apigw.get_base_path_mappings(domainName=domain).get("items", [])
    assert mappings == [], f"expected no base path mappings to exist, found {mappings}"

    rest_api_id, stage_name = _create_deployed_api(ctx, apigw)
    apigw.create_base_path_mapping(
        domainName=domain, restApiId=rest_api_id, stage=stage_name, basePath="ok"
    )
    ctx.on_cleanup(
        lambda: apigw.delete_base_path_mapping(domainName=domain, basePath="ok")
    )
    mapping = apigw.get_base_path_mapping(domainName=domain, basePath="ok")
    assert mapping["restApiId"] == rest_api_id, (
        f"expected restApiId {rest_api_id}, got {mapping['restApiId']}"
    )
    assert mapping["stage"] == stage_name, (
        f"expected stage {stage_name}, got {mapping['stage']}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert(common_name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _create_deployed_api(ctx, apigw):
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bpm-api-"), tags={"sim2real": CHECK}
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    resources = apigw.get_resources(restApiId=rest_api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    stage_name = "prod"
    apigw.create_deployment(restApiId=rest_api_id, stageName=stage_name)
    return rest_api_id, stage_name


def _delete_certificate_when_released(acm, arn: str, timeout_s: float = 300.0) -> None:
    """ACM reports a certificate in use for a while after its domain name is deleted; retry
    DeleteCertificate on ResourceInUseException until a bounded deadline."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or _time.monotonic() > deadline:
                raise
            _time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
