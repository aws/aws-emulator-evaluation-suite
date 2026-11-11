"""create-base-path-mapping-nonexistent-restapi-fails."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "create-base-path-mapping-nonexistent-restapi-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBasePathMapping naming a nonexistent restApiId fails with BadRequestException and creates no
    mapping, while the same call naming a deployed REST API succeeds."""
    apigw = ctx.client("apigateway")
    domain = _create_domain_name_best_effort(ctx)

    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain, restApiId="sim2real0000nonexist", basePath=""
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for a nonexistent restApiId, got {code!r}"
    )
    assert message == "Invalid REST API identifier specified", f"unexpected BadRequestException message {message!r}"

    # confirm no mapping was actually created on the real (existing) domain
    mappings = apigw.get_base_path_mappings(domainName=domain).get("items", [])
    assert mappings == [], f"expected no base path mappings to be created, found {mappings}"

    # positive control: the same domain + same basePath maps cleanly to a real,
    # deployed REST API -- so the earlier rejection is specific to the nonexistent id.
    # basePath="" is the request-body spelling of the root base path, but GetBasePathMapping
    # and DeleteBasePathMapping take it as a URI path segment, where AWS requires the literal
    # string "(none)" instead (an empty path segment does not address the resource).
    rest_api_id, stage_name = _create_deployed_api(ctx, apigw)
    apigw.create_base_path_mapping(domainName=domain, restApiId=rest_api_id, stage=stage_name, basePath="")
    ctx.on_cleanup(lambda: apigw.delete_base_path_mapping(domainName=domain, basePath="(none)"))

    mapping = apigw.get_base_path_mapping(domainName=domain, basePath="(none)")
    assert mapping["restApiId"] == rest_api_id, (
        f"expected positive-control mapping to point at {rest_api_id!r}, got {mapping!r}"
    )
    assert mapping["stage"] == stage_name, (
        f"expected positive-control mapping stage {stage_name!r}, got {mapping!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_domain_name_best_effort(ctx) -> str:
    """Create a real DomainName resource, falling back to importing a self-signed
    ACM certificate if API Gateway requires one for the domain to be created."""
    apigw = ctx.client("apigateway")
    domain = (ctx.unique_name("sim2real-bpm-") + ".example.com").lower()

    from botocore.exceptions import ClientError

    try:
        apigw.create_domain_name(domainName=domain, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))
        return domain
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "BadRequestException":
            raise

    cert_arn = _import_self_signed_cert(ctx, domain)
    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))
    return domain


def _create_deployed_api(ctx, apigw) -> tuple[str, str]:
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-bpm-api-"), tags={"sim2real": CHECK})
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


def _import_self_signed_cert(ctx, common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
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
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


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
