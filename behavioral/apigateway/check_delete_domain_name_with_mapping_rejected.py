"""delete-domain-name-with-mapping-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-domain-name-with-mapping-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_CLEANUP_S = 840.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRestApi fails with BadRequestException while an active base path mapping points at the REST
    API, and the API is not removed; once the mapping is cleared the delete succeeds, and the domain
    then deletes and GetDomainName reports NotFoundException."""
    apigw = ctx.client("apigateway")

    domain = f"{ctx.unique_name('sim2real-behav-domdel-')}.example.com".lower()
    cert_arn = _self_signed_cert_arn(ctx, domain)
    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(domainName=domain)))
    _poll_until(
        lambda: apigw.get_domain_name(domainName=domain)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=90,
        interval_s=5,
    )

    name = ctx.unique_name("sim2real-behav-domdel-api-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName="live")

    base_path = "v1"
    apigw.create_base_path_mapping(domainName=domain, basePath=base_path, restApiId=rest_api_id, stage="live")

    # Guard against read-after-write races: make sure the mapping is durably visible
    # (both via direct Get and via the List) before relying on it to block the delete.
    _poll_until(
        lambda: apigw.get_base_path_mapping(domainName=domain, basePath=base_path).get("basePath"),
        lambda bp: bp == base_path,
        timeout_s=30,
        interval_s=3,
    )
    _poll_until(
        lambda: {m["basePath"] for m in apigw.get_base_path_mappings(domainName=domain).get("items", [])},
        lambda mappings: base_path in mappings,
        timeout_s=30,
        interval_s=3,
    )

    # Delete the REST API while an active base path mapping still points at it.
    code, message = _error(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        f"Deleting RestApi {rest_api_id} failed. Please remove all base path mappings related to "
        f"the RestApi in your domains: {domain}"
    ), f"unexpected message: {message!r}"

    # The forbidden effect did not happen: the REST API still exists.
    unaffected = apigw.get_rest_api(restApiId=rest_api_id)
    assert unaffected["id"] == rest_api_id, (
        f"expected rest api {rest_api_id!r} to still exist after the rejected delete, "
        f"got {unaffected.get('id')!r}"
    )

    # Positive control: after removing the precondition (the mapping), the delete succeeds.
    apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)
    apigw.delete_rest_api(restApiId=rest_api_id)
    after_code, after_message = _error(lambda: apigw.get_rest_api(restApiId=rest_api_id))
    assert after_code == "NotFoundException", f"expected NotFoundException after delete, got {after_code!r}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert after_message == f"Invalid API identifier specified {account_id}:{rest_api_id}", (
        f"unexpected message: {after_message!r}"
    )

    # The domain deletes once its mapping is gone.
    apigw.delete_domain_name(domainName=domain)
    domain_gone_code, domain_gone_message = _error(lambda: apigw.get_domain_name(domainName=domain))
    assert domain_gone_code == "NotFoundException", (
        f"expected NotFoundException after domain delete, got {domain_gone_code!r}"
    )
    assert domain_gone_message == "Invalid domain name identifier specified", f"unexpected message: {domain_gone_message!r}"


def _delete_cert(acm, cert_arn: str) -> None:
    """Teardown: ACM answers ResourceInUseException until API Gateway releases a deleted domain's
    certificate, so retry it every 2 s to the deadline; not-found is done, anything else raises."""
    deadline = time.monotonic() + _CLEANUP_S
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
        time.sleep(2)


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last result: {last!r})")


def _self_signed_cert_arn(ctx, common_name: str) -> str:
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
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert(acm, arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
