"""delete-domain-name-with-dependent-base-path-mapping-conflict."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError

CHECK = "delete-domain-name-with-dependent-base-path-mapping-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName succeeds while a BasePathMapping still references the domain (ConflictException
    is not among its documented errors): the domain is gone afterwards and the orphaned mapping reads
    as not found."""
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    # The regional certificate must actually cover the domain name we are about to create
    # (AWS validates the cert's CN/SAN against the requested domain), so generate the
    # self-signed certificate for the *same* name used in create_domain_name below.
    domain_name = ctx.unique_name("sim2real-apigw-domain-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert_pem(domain_name)

    cert_arn = acm.import_certificate(
        Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_cert_when_released(acm, cert_arn)))

    api_id, stage_name = _create_minimal_deployed_api(ctx)

    _create_domain_name_with_retry(
        apigw,
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(domainName=domain_name)))

    apigw.create_base_path_mapping(
        domainName=domain_name, restApiId=api_id, stage=stage_name, basePath="v1"
    )

    # The delete succeeds outright; it is not rejected by the dependent mapping.
    apigw.delete_domain_name(domainName=domain_name)

    code, message = _error(lambda: apigw.get_domain_name(domainName=domain_name))
    assert code == "NotFoundException", f"expected NotFoundException reading the deleted domain, got {code!r}"
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"

    # The mapping that referenced the now-deleted domain is gone too (there is no domain left
    # for it to attach to); it must not still resolve.
    code, message = _error(lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="v1"))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading the orphaned mapping, got {code!r}"
    )
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"

    # A mutation against the dead domain also fails, not just a read: the identifier is fully
    # gone, not merely hidden from GetDomainName.
    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain_name, restApiId=api_id, stage=stage_name, basePath="v2"
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException creating a mapping against the deleted domain, got {code!r}"
    )
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"


def _self_signed_cert_pem(common_name: str) -> tuple[str, str]:
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
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _create_minimal_deployed_api(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    return api_id, stage_name


def _create_domain_name_with_retry(apigw, timeout_s: float = 300.0, interval_s: float = 10.0, **kwargs):
    """CreateDomainName is subject to a low account-level TPS limit; retry with a bounded
    backoff on throttling instead of letting a transient TooManyRequestsException fail the
    check (this is not the behavior under test)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


# budget.cleanup_timeout for behavioral/apigateway
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    deleted domain name as a user, up to the cleanup budget; any other error raises."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
