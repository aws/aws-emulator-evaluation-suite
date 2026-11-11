"""e2e-custom-domain-base-path-routing."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-custom-domain-base-path-routing"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A REGIONAL custom domain with two base path mappings routes each base path
    to the correct RestApi/stage pair, and removing the mappings then the domain
    leaves no dangling base path mapping or domain resource behind."""
    domain_name = f"{ctx.unique_name('sim2real-domain-')}.example.com"

    cert_pem, key_pem = _self_signed_cert(domain_name)

    acm = ctx.client("acm")
    imported = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": "e2e-custom-domain-base-path-routing"}],
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete_certificate(acm, cert_arn))

    apigw = ctx.client("apigateway")
    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "e2e-custom-domain-base-path-routing"},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain_name(apigw, domain_name))

    # Base path mappings are a control-plane association and do not require the
    # domain's DNS/certificate provisioning (domainNameStatus) to reach AVAILABLE
    # first; we only assert it never reports FAILED before wiring the mappings.
    status = apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
    assert status != "FAILED", f"domain name creation reported FAILED: {status!r}"

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-domainapi-"),
        tags={"sim2real": "e2e-custom-domain-base-path-routing"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_delete_rest_api(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

    deployment = apigw.create_deployment(restApiId=api_id)
    apigw.create_stage(restApiId=api_id, stageName="prod", deploymentId=deployment["id"])
    apigw.create_stage(restApiId=api_id, stageName="beta", deploymentId=deployment["id"])

    apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, basePath="", stage="prod")
    apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, basePath="v2", stage="beta")

    all_mappings = _poll_get_base_path_mappings(apigw, domain_name, expected_count=2)
    by_base_path = {
        ("" if m.get("basePath") in (None, "(none)") else m.get("basePath")): m for m in all_mappings
    }

    root_mapping = by_base_path[""]
    assert root_mapping["restApiId"] == api_id, (
        f"root base path mapping resolved to restApiId={root_mapping['restApiId']!r}, expected {api_id!r}"
    )
    assert root_mapping["stage"] == "prod", f"root base path mapping resolved to stage {root_mapping['stage']!r}, expected 'prod'"

    v2_mapping = by_base_path["v2"]
    assert v2_mapping["restApiId"] == api_id, (
        f"'v2' base path mapping resolved to restApiId={v2_mapping['restApiId']!r}, expected {api_id!r}"
    )
    assert v2_mapping["stage"] == "beta", f"'v2' base path mapping resolved to stage {v2_mapping['stage']!r}, expected 'beta'"

    apigw.delete_base_path_mapping(domainName=domain_name, basePath="(none)")
    mapping_not_found = ("NotFoundException", "Invalid base path mapping identifier specified")
    err = _error(lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="(none)"))
    assert err == mapping_not_found, f"expected {mapping_not_found!r} reading the deleted root mapping, got {err!r}"

    # The dead mapping is unusable, not just unreadable: a mutation naming it must also fail.
    err = _error(
        lambda: apigw.update_base_path_mapping(
            domainName=domain_name,
            basePath="(none)",
            patchOperations=[{"op": "replace", "path": "/stage", "value": "beta"}],
        )
    )
    assert err == mapping_not_found, f"expected {mapping_not_found!r} updating the deleted root mapping, got {err!r}"

    apigw.delete_base_path_mapping(domainName=domain_name, basePath="v2")
    remaining = apigw.get_base_path_mappings(domainName=domain_name)["items"]
    assert remaining == [], f"expected no dangling base path mappings, found {remaining!r}"

    # No mappings remain, so the domain itself can be removed cleanly.
    apigw.delete_domain_name(domainName=domain_name)
    domain_not_found = ("NotFoundException", "Invalid domain name identifier specified")
    err = _error(lambda: apigw.get_domain_name(domainName=domain_name))
    assert err == domain_not_found, f"expected {domain_not_found!r} reading the deleted domain, got {err!r}"

    # The dead domain is unusable, not just unreadable: a mutation naming it must also fail.
    err = _error(
        lambda: apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, basePath="late")
    )
    assert err == domain_not_found, f"expected {domain_not_found!r} mapping onto the deleted domain, got {err!r}"


def _self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_get_base_path_mappings(apigw, domain_name: str, expected_count: int, timeout_s: float = 60.0) -> list:

    # Mappings on a freshly created custom domain can take a moment to become
    # fully readable; poll until all created mappings are visible and populated.
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = apigw.get_base_path_mappings(domainName=domain_name).get("items", [])
        if len(last) >= expected_count and all("restApiId" in m for m in last):
            return last
        time.sleep(3.0)
    raise AssertionError(f"GetBasePathMappings never returned {expected_count} populated records; last={last!r}")


def _safe_delete_certificate(acm, cert_arn: str) -> None:
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300
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


def _safe_delete_domain_name(apigw, domain_name: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain_name)
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_rest_api(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
