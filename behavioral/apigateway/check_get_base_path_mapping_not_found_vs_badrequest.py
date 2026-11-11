"""get-base-path-mapping-not-found-vs-badrequest."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "get-base-path-mapping-not-found-vs-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

_MAPPING_NOT_FOUND = "Invalid base path mapping identifier specified"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBasePathMapping on a domain with one mapping resolves the mapped basePath and returns
    NotFoundException for two different unmapped ones; after the mapping is deleted, the
    formerly mapped basePath returns NotFoundException too, so the lookup reflects live state."""
    apigw = ctx.client("apigateway")
    cleanup_deadline: dict = {}
    domain_name = f"{ctx.unique_name('sim2real-bpm-').lower()}.example.com"

    cert_pem, key_pem = _self_signed_cert(ctx, domain_name)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn, cleanup_deadline))

    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain_name))
    _wait_domain_available(ctx, apigw, domain_name)

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"))["id"]
    ctx.on_cleanup(lambda: _retry_throttled_teardown(
        lambda: apigw.delete_rest_api(restApiId=api_id), cleanup_deadline))
    root_id = _root_resource_id(apigw, api_id)
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")

    base_path = "v1"
    apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, stage="test", basePath=base_path)

    def _cleanup_mapping():
        try:
            apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup_mapping)

    # Positive control: the mapping we actually created resolves.
    mapped = apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    assert mapped["restApiId"] == api_id and mapped["stage"] == "test", (
        f"expected restApiId={api_id!r} stage='test', got restApiId={mapped.get('restApiId')!r} "
        f"stage={mapped.get('stage')!r}"
    )

    code_missing, message_missing = _client_error(
        lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="doesnotexist")
    )
    assert code_missing == "NotFoundException", f"expected NotFoundException for unmapped basePath, got {code_missing}"
    assert message_missing == _MAPPING_NOT_FOUND, (
        f"unexpected NotFoundException message {message_missing!r}"
    )

    # A domainName that was never created is resolved like an unmapped basePath: the error path is a
    # lookup failure, with no separate BadRequestException for an unknown domain.
    unknown_domain = f"{ctx.unique_name('sim2real-bpm-unknown-').lower()}.example.com"
    code_unknown_domain, message_unknown_domain = _client_error(
        lambda: apigw.get_base_path_mapping(domainName=unknown_domain, basePath=base_path)
    )
    assert code_unknown_domain == "NotFoundException", (
        f"expected NotFoundException for a domainName that was never created, got {code_unknown_domain}"
    )
    assert message_unknown_domain == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message {message_unknown_domain!r}"
    )

    # A second unmapped basePath on the same domain is NotFound too: the rejection is keyed on the
    # basePath value, not a single cached miss.
    code_other_missing, message_other_missing = _client_error(
        lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="also-missing")
    )
    assert code_other_missing == "NotFoundException", (
        f"expected NotFoundException for a second unmapped basePath, got {code_other_missing}"
    )
    assert message_other_missing == _MAPPING_NOT_FOUND, (
        f"unexpected NotFoundException message {message_other_missing!r}"
    )

    # After the mapping is deleted, the formerly valid basePath returns NotFoundException too:
    # the lookup tracks live mapping state.
    apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
    code_after_delete, message_after_delete = _client_error(
        lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    )
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException for the just-deleted basePath, got {code_after_delete}"
    )
    assert message_after_delete == _MAPPING_NOT_FOUND, (
        f"unexpected NotFoundException message {message_after_delete!r}"
    )


def _root_resource_id(apigw: Any, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, so a
    target resolving a mapping real AWS does not have is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


# budget.cleanup_timeout for behavioral/apigateway; one deadline shared by every teardown of a run.
_CLEANUP_S = 900.0


def _retry_teardown(fn, retry_code: str, started: dict) -> None:
    """Call fn, retrying `retry_code` every 2 s to the run's shared cleanup deadline; raise the rest."""
    from botocore.exceptions import ClientError

    deadline = started.setdefault("t", time.monotonic() + _CLEANUP_S)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != retry_code or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _retry_throttled_teardown(fn, started: dict) -> None:
    """DeleteRestApi has a low account-wide rate limit; wait out TooManyRequestsException."""
    _retry_teardown(fn, "TooManyRequestsException", started)


def _delete_certificate(acm, arn: str, started: dict) -> None:
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    _retry_teardown(lambda: acm.delete_certificate(CertificateArn=arn), "ResourceInUseException", started)


def _self_signed_cert(ctx, domain_name: str) -> tuple[bytes, bytes]:
    """Generate a throwaway self-signed cert/key pair via the openssl CLI.

    ACM's ImportCertificate accepts self-signed certs (it does not validate a trust
    chain), but API Gateway's CreateDomainName DOES check that the certificate covers
    the requested domain name, so the cert's CN must match `domain_name` exactly.
    """
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        require_tools("openssl")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-nodes", "-subj", f"/CN={domain_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _wait_domain_available(ctx, apigw, domain_name: str, timeout_s: float = 240.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
        if status == "AVAILABLE":
            return
        if status == "FAILED":
            raise AssertionError(f"domain name {domain_name} entered FAILED status while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"domain name {domain_name} did not become AVAILABLE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
