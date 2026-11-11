"""delete-domain-name-with-active-basepath-mapping-conflict."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

CHECK = "delete-domain-name-with-active-basepath-mapping-conflict"
GROUP = "concurrency"
SERVICES = ["apigateway"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName succeeds even while a base path mapping still references it (AWS does
    not gate domain deletion on the presence of base path mappings); the deletion removes both
    the domain name and the mapping that pointed at it."""
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    domain_name = ctx.unique_name("sim2real-behav-domain-").lower() + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, acm, domain_name)

    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(domainName=domain_name)))

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain_name)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        ctx=ctx,
        timeout_s=240.0,
        what="the domain name to leave PENDING",
    )
    if status != "AVAILABLE":
        raise AssertionError(
            f"regional domain name did not reach AVAILABLE status within timeout (status={status})",
        )

    api_name = ctx.unique_name("sim2real-behav-api-")
    rest_api_id = apigw.create_rest_api(name=api_name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = [r for r in apigw.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName="prod")

    base_path = "v1"
    apigw.create_base_path_mapping(domainName=domain_name, restApiId=rest_api_id, stage="prod", basePath=base_path)

    # On real AWS, DeleteDomainName is NOT blocked by an active base path mapping (unlike, e.g.,
    # deleting a REST API that is still mapped). The domain (and the mapping that referenced it)
    # is deleted outright. Assert that this actually happens end-to-end rather than assuming a
    # ConflictException that AWS does not raise here.
    # DeleteDomainName succeeds despite the active mapping; a refusal raises ClientError here.
    apigw.delete_domain_name(domainName=domain_name)

    final_status = _poll_until(
        lambda: _get_domain_status_or_none(apigw, domain_name),
        lambda s: s is None,
        ctx=ctx,
        timeout_s=180.0,
        what="the deleted domain name to disappear",
    )
    assert final_status is None, "domain name was not actually deleted"

    # The base path mapping that referenced the now-deleted domain is gone with it.
    mapping_code, mapping_message = _error(
        lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    )
    assert mapping_code == "NotFoundException", (
        f"expected the orphaned base path mapping lookup to 404, got {mapping_code!r}"
    )
    assert mapping_message == "Invalid domain name identifier specified", f"unexpected message: {mapping_message!r}"


def _import_self_signed_cert(ctx, acm: Any, domain_name: str) -> str:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = str(Path(tmp) / "key.pem")
            cert_path = str(Path(tmp) / "cert.pem")
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key_path, "-out", cert_path, "-days", "365",
                    "-subj", f"/CN={domain_name}",
                ],
                check=True, capture_output=True,
            )
            cert_bytes = Path(cert_path).read_bytes()
            key_bytes = Path(key_path).read_bytes()
    except subprocess.CalledProcessError as e:
        raise AssertionError(f"openssl failed to generate a self-signed certificate: {e}")

    resp = acm.import_certificate(
        Certificate=cert_bytes, PrivateKey=key_bytes, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


#: How long a teardown waits for the deleted domain name to release its certificate.
CERT_RELEASE_TIMEOUT_S = 600.0


def _delete_certificate_when_released(acm: Any, arn: str) -> None:
    """Delete the imported certificate once no resource of this account uses it.

    A deleted custom domain keeps its certificate listed as in use for a while; DeleteCertificate
    is retried every 2 s while that lasts. A certificate that only API Gateway's own load balancers
    (another account's resources) still hold is left: the refusal is raised for the runner to
    record as such.
    """
    own = arn.split(":")[4]
    deadline = time.monotonic() + CERT_RELEASE_TIMEOUT_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            users = acm.describe_certificate(CertificateArn=arn)["Certificate"].get("InUseBy") or []
            if users and all((u.split(":") + [""] * 5)[4] not in ("", own) for u in users):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"certificate {arn} still in use by {users!r} {CERT_RELEASE_TIMEOUT_S:.0f}s "
                    "after its domain name was deleted"
                ) from exc
        time.sleep(2.0)

def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _get_domain_status_or_none(apigw: Any, domain_name: str) -> str | None:
    try:
        return apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NotFoundException":
            return None
        raise


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, ctx, timeout_s: float, what: str
) -> Any:
    """probe() every 2 s until predicate holds or timeout_s passes; returns the last value.

    A wait the runner's budget cuts short is no verdict: it raises a not-graded TimeoutError.
    """
    start = time.monotonic()
    left = ctx.time_left()
    cap_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    while True:
        last = probe()
        if predicate(last) or time.monotonic() - start >= timeout_s:
            return last
        if time.monotonic() - start >= cap_s:
            raise TimeoutError(
                f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                f"the {timeout_s:.0f}s wait for {what} ended; last saw {last!r}; not graded"
            )
        time.sleep(2.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
