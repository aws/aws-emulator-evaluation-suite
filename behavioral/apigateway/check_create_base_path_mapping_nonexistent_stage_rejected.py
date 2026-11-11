"""create-base-path-mapping-nonexistent-stage-rejected."""
from __future__ import annotations

import datetime
import re
import time
import uuid

from behavioral_harness import tags

CHECK = "create-base-path-mapping-nonexistent-stage-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBasePathMapping referencing a stage that was never deployed is rejected, and no
    mapping is created; the same call with a real, deployed stage then succeeds (positive
    control) on the exact same domain/basePath."""
    apigw = ctx.client("apigateway")
    domain = _dns_label(ctx.unique_name("sim2real-nostage-domain-")) + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _create_domain_name_retrying(
        apigw, domainName=domain, endpointConfiguration={"types": ["REGIONAL"]}, regionalCertificateArn=cert_arn
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-nostage-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ctx.on_cleanup(lambda: _delete_mapping_if_present(apigw, domain, "v1"))

    # No deployment/stage exists on this API yet: referencing "prod" as the mapping's stage
    # must be refused.
    err = _error(
        lambda: apigw.create_base_path_mapping(domainName=domain, restApiId=api_id, basePath="v1", stage="prod")
    )
    expected = ("BadRequestException", "Invalid stage identifier specified")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # The forbidden mapping was never created. When a domain has no mappings, real AWS omits the
    # "items" key from the response entirely (rather than returning an empty list).
    listed = apigw.get_base_path_mappings(domainName=domain).get("items", [])
    assert listed == [], listed

    # Positive control: deploy the stage for real, then the identical call succeeds.
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    created = apigw.create_base_path_mapping(domainName=domain, restApiId=api_id, basePath="v1", stage="prod")
    assert created["stage"] == "prod", f"expected create response stage 'prod', got {created.get('stage')!r}"
    assert created["restApiId"] == api_id, f"expected create response restApiId {api_id!r}, got {created.get('restApiId')!r}"

    # Terminal read is independent of the mutating call: fetch the mapping back through
    # GetBasePathMapping rather than trusting CreateBasePathMapping's own echoed response.
    fetched = apigw.get_base_path_mapping(domainName=domain, basePath="v1")
    assert fetched["stage"] == "prod", f"expected fetched mapping stage 'prod', got {fetched.get('stage')!r}"
    assert fetched["restApiId"] == api_id, f"expected fetched mapping restApiId {api_id!r}, got {fetched.get('restApiId')!r}"


def _dns_label(raw: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_domain_name_retrying(apigw, timeout_s: float = 180.0, interval_s: float = 10.0, **kwargs):
    """CreateDomainName is subject to an account-level rate limit that botocore's built-in retry
    budget (5 attempts) can exhaust during busy periods; retry with a longer, bounded backoff on
    TooManyRequestsException rather than treating the throttle as a hard failure."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_mapping_if_present(apigw, domain: str, base_path: str) -> None:
    from botocore.exceptions import ClientError

    try:
        apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _generate_self_signed_cert(common_name: str) -> tuple[str, str]:
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
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _delete_cert_retrying(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ResourceInUseException",) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _import_self_signed_cert(ctx, common_name: str) -> str:
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-behav", "Value": str(uuid.uuid4())}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
