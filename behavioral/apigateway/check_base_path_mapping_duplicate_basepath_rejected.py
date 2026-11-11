"""base-path-mapping-duplicate-basepath-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "base-path-mapping-duplicate-basepath-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateBasePathMapping with an already-mapped basePath is rejected with ConflictException,
    leaving the original mapping untouched; mapping a distinct basePath (positive control) succeeds."""
    apigw = ctx.client("apigateway")

    domain = f"{ctx.unique_name('sim2real-behav-bpmdup-')}.example.com".lower()
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

    rest_api_id_1, stage_1 = _build_api_with_stage(ctx, apigw, "one")
    rest_api_id_2, stage_2 = _build_api_with_stage(ctx, apigw, "two")

    base_path = "v1"
    apigw.create_base_path_mapping(domainName=domain, basePath=base_path, restApiId=rest_api_id_1, stage=stage_1)
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)))

    # Break exactly one precondition: reuse the same basePath on the same domain for a different API.
    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain, basePath=base_path, restApiId=rest_api_id_2, stage=stage_2
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Base path already exists for this domain name", f"unexpected message {message!r}"

    # The forbidden effect did not happen: the mapping still points at the first API/stage.
    unaffected = apigw.get_base_path_mapping(domainName=domain, basePath=base_path)
    assert unaffected["restApiId"] == rest_api_id_1, (
        f"expected restApiId {rest_api_id_1!r} untouched, got {unaffected['restApiId']!r}"
    )
    assert unaffected["stage"] == stage_1, f"expected stage {stage_1!r} untouched, got {unaffected['stage']!r}"

    # Positive control: the same operation succeeds once the precondition (distinct basePath) is met.
    other_base_path = "v2"
    apigw.create_base_path_mapping(
        domainName=domain, basePath=other_base_path, restApiId=rest_api_id_2, stage=stage_2
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: apigw.delete_base_path_mapping(domainName=domain, basePath=other_base_path))
    )

    # Terminal assertion is an independent read (GetBasePathMapping), not the CreateBasePathMapping
    # response itself — the mapping must actually be visible at the destination, not merely echoed.
    control = apigw.get_base_path_mapping(domainName=domain, basePath=other_base_path)
    assert control["restApiId"] == rest_api_id_2, control
    assert control["stage"] == stage_2, control


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NotFoundException",) or
            (exc.response["Error"]["Code"] == "BadRequestException"
             and "Invalid REST API identifier" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last result: {last!r})")


def _delete_cert_when_released(acm, arn: str, *, timeout_s: float = 240.0) -> None:
    """DeleteCertificate, waiting out ResourceInUseException while ACM still sees the just-deleted
    domain name as a user of the certificate; any other error, or a cert still in use at the
    deadline, propagates so a leaked certificate fails the cleanup instead of passing silently."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


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
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _build_api_with_stage(ctx, apigw, tag):
    name = ctx.unique_name(f"sim2real-behav-bpmdup-api-{tag}-")
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
    return rest_api_id, "live"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
