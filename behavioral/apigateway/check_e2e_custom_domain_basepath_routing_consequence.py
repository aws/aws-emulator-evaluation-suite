"""e2e-custom-domain-basepath-routing-consequence."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-custom-domain-basepath-routing-consequence"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a custom domain is AVAILABLE its base path mapping targets the deployed API/stage and
    follows a remap; deleting the mapping and the domain makes their reads and writes 404."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    fake_domain = f"{ctx.unique_name('sim2real-e2e-domain-')}.example.com".lower()

    # --- mint + import a self-signed cert for fake_domain (no real domain ownership needed
    # for ACM import, unlike an ACM-issued/DNS-validated certificate) ---
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fake_domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fake_domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    imported = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": "custom-domain-basepath-routing-consequence"}],
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_ignore_missing(acm, cert_arn))

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-e2e-domapi-"),
        tags={"sim2real": "custom-domain-basepath-routing-consequence"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_ignore_missing(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="hello")
    resource_id = resource["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "domain-routed"}'},
    )
    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    # A second stage lets us prove the mapping resolves to the SPECIFIC stage it names, not
    # just to "some" stage of the API.
    deployment2 = apigw.create_deployment(restApiId=api_id)
    other_stage_name = "other"
    apigw.create_stage(
        restApiId=api_id, stageName=other_stage_name, deploymentId=deployment2["id"]
    )
    ctx.on_cleanup(
        lambda: _delete_stage_ignore_missing(apigw, api_id, other_stage_name)
    )

    domain = apigw.create_domain_name(
        domainName=fake_domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "custom-domain-basepath-routing-consequence"},
    )
    ctx.on_cleanup(lambda: _delete_domain_ignore_missing(apigw, fake_domain))

    domain = _poll_until(
        lambda: apigw.get_domain_name(domainName=fake_domain),
        lambda d: d["domainNameStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert domain["domainNameStatus"] == "AVAILABLE", (
        f"expected domainNameStatus=AVAILABLE, got {domain['domainNameStatus']!r} "
        f"({domain.get('domainNameStatusMessage')!r})"
    )
    assert domain["regionalDomainName"], "AVAILABLE domain must report a non-empty regionalDomainName"

    apigw.create_base_path_mapping(
        domainName=fake_domain, restApiId=api_id, basePath="v1", stage=stage_name
    )
    mapping = apigw.get_base_path_mapping(domainName=fake_domain, basePath="v1")
    assert mapping["restApiId"] == api_id, (
        f"expected mapping restApiId={api_id!r}, got {mapping['restApiId']!r}"
    )
    assert mapping["stage"] == stage_name, (
        f"expected mapping stage={stage_name!r}, got {mapping['stage']!r}"
    )
    assert mapping["stage"] != other_stage_name, (
        f"mapping stage {mapping['stage']!r} must not already equal the OTHER stage "
        f"{other_stage_name!r} before any remap"
    )

    # Re-pointing the SAME base path to the OTHER stage is the real routing consequence a
    # client-facing proxy would need to pick up: the mapping resource itself must reflect the
    # new target immediately, deterministically, from the server's point of view.
    apigw.update_base_path_mapping(
        domainName=fake_domain,
        basePath="v1",
        patchOperations=[{"op": "replace", "path": "/stage", "value": other_stage_name}],
    )
    remapped = apigw.get_base_path_mapping(domainName=fake_domain, basePath="v1")
    assert remapped["stage"] == other_stage_name, (
        f"expected remapped mapping stage={other_stage_name!r}, got {remapped['stage']!r}"
    )

    # Remove the mapping; the route it drove must now be gone (404 on the mapping resource),
    # and the dead mapping must also be unusable -- a mutation on it must fail the same way.
    apigw.delete_base_path_mapping(domainName=fake_domain, basePath="v1")
    mapping_not_found = ("NotFoundException", "Invalid base path mapping identifier specified")
    err_after_unmap = _error(
        lambda: apigw.get_base_path_mapping(domainName=fake_domain, basePath="v1")
    )
    assert err_after_unmap == mapping_not_found, (
        f"expected GetBasePathMapping on a deleted mapping to 404 with {mapping_not_found!r}, "
        f"got {err_after_unmap!r}"
    )
    err_mutate_after_unmap = _error(
        lambda: apigw.update_base_path_mapping(
            domainName=fake_domain,
            basePath="v1",
            patchOperations=[{"op": "replace", "path": "/stage", "value": stage_name}],
        )
    )
    assert err_mutate_after_unmap == mapping_not_found, (
        f"expected UpdateBasePathMapping on a deleted mapping to fail with {mapping_not_found!r}, "
        f"got {err_mutate_after_unmap!r}"
    )

    # And the domain itself, once deleted, also 404s -- the whole routing surface is gone --
    # and is unusable: a mutation attempt (a new mapping against it) must fail too.
    apigw.delete_domain_name(domainName=fake_domain)
    domain_not_found = ("NotFoundException", "Invalid domain name identifier specified")
    err_after_domain = _error(lambda: apigw.get_domain_name(domainName=fake_domain))
    assert err_after_domain == domain_not_found, (
        f"expected GetDomainName on a deleted domain to 404 with {domain_not_found!r}, "
        f"got {err_after_domain!r}"
    )
    err_mutate_after_domain = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=fake_domain, restApiId=api_id, basePath="v2", stage=stage_name
        )
    )
    assert err_mutate_after_domain == domain_not_found, (
        f"expected CreateBasePathMapping against a deleted domain to fail with {domain_not_found!r}, "
        f"got {err_mutate_after_domain!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_rest_api_ignore_missing(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_stage_ignore_missing(apigw, api_id: str, stage_name: str) -> None:
    try:
        apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_domain_ignore_missing(apigw, domain_name: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_cert_ignore_missing(acm, cert_arn: str) -> None:
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

