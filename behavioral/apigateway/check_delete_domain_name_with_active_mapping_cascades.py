"""delete-domain-name-with-active-mapping-cascades."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-domain-name-with-active-mapping-cascades"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName succeeds while a base path mapping is active and cascades: afterwards both
    the domain and its mapping return NotFoundException, so the mapping is not left dangling."""
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")
    api_id, _root_id = _create_deployable_api(ctx)

    deployment_id = apigw.create_deployment(restApiId=api_id, description="d1")["id"]
    apigw.create_stage(restApiId=api_id, stageName="live", deploymentId=deployment_id)

    domain_name = f"{ctx.unique_name('sim2real-behav-dnmap-')}.example.com".lower()
    # Real AWS rejects a bare CreateDomainName ("A certificate was not provided for the endpoint
    # type EDGE"); use a REGIONAL domain backed by a self-signed cert imported into ACM.
    cert_arn = _import_self_signed_cert(ctx, acm, domain_name)
    _create_domain_name_with_retry(
        apigw,
        domainName=domain_name,
        endpointConfiguration={"types": ["REGIONAL"]},
        regionalCertificateArn=cert_arn,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(domainName=domain_name)))

    apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, basePath="v1", stage="live")
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath="v1")))

    # DeleteDomainName succeeds despite the active mapping.
    apigw.delete_domain_name(domainName=domain_name)

    # The domain name itself is gone.
    code, message = _error(lambda: apigw.get_domain_name(domainName=domain_name))
    assert code == "NotFoundException", f"expected NotFoundException for the domain after delete, got {code}"
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"

    # The mapping was cascade-removed along with its owning domain, not left dangling.
    code, message = _error(lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="v1"))
    assert code == "NotFoundException", (
        f"expected NotFoundException for the base path mapping after its domain was deleted, got {code}"
    )
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


_GONE = frozenset({"NotFoundException", "ResourceNotFoundException"})
_BUSY = frozenset({"TooManyRequestsException", "ConflictException", "ResourceInUseException"})


def _safe(fn) -> None:
    """Run one teardown call: a resource already gone is fine; a throttled or still-in-use one
    is retried every 2 s for up to 300 s; any other error raises."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _import_self_signed_cert(ctx, acm, domain: str) -> str:
    """Mint a throwaway self-signed cert and import it into ACM (REGIONAL custom domain names
    accept an imported certificate — no public DNS validation is required)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        proc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain}",
            ],
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(f"unreachable: openssl cert generation failed: {proc.stderr!r}")
        cert_pem, key_pem = cert_path.read_bytes(), key_path.read_bytes()
    try:
        cert_arn = acm.import_certificate(
            Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
        )["CertificateArn"]
    except ClientError as e:
        raise AssertionError(f"unreachable: ACM import_certificate failed ({e.response['Error']['Code']})")
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


def _create_domain_name_with_retry(apigw, *, attempts: int = 6, base_delay: float = 5.0, **kwargs):
    """CreateDomainName is subject to a low per-account request rate; retry with backoff on
    TooManyRequestsException rather than treating account-level throttling as a check failure."""
    for attempt in range(attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "TooManyRequestsException" or attempt == attempts - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))
    raise AssertionError("unreachable")


def _create_deployable_api(ctx):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
