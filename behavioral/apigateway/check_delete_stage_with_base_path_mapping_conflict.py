"""delete-stage-with-base-path-mapping-conflict."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError

CHECK = "delete-stage-with-base-path-mapping-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStage fails with BadRequestException (not ConflictException) while a BasePathMapping on a
    custom domain points at the stage, and the stage survives; once the mapping is removed the identical
    delete succeeds."""
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    api_id, stage_name = _create_deployed_api_with_explicit_stage(ctx)

    # The regional certificate must actually cover the domain name we are about to create
    # (AWS validates the cert's CN/SAN against the requested domain), so generate the
    # self-signed certificate for the *same* name used in create_domain_name below.
    domain_name = ctx.unique_name("sim2real-apigw-domain-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert_pem(domain_name)

    cert_arn = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_cert_when_released(acm, cert_arn)))

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
    # Registered here (after domain_name's cleanup, before it in LIFO order) so a failure
    # anywhere below still removes the mapping before the domain_name delete is attempted —
    # otherwise that delete conflicts on the still-active mapping and is swallowed by `_safe`,
    # leaking the domain name and certificate too.
    ctx.on_cleanup(
        lambda: _safe(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath="v1"))
    )

    code, message = _client_error(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting a stage still referenced by a base path mapping, "
        f"got {code!r}"
    )
    assert message == (
        f"Deleting stage {stage_name} failed. Please remove all base path mappings related to "
        f"the stage in your domains: {domain_name}"
    ), message

    # The rejected delete must not have mutated the stage.
    still_there = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert still_there["stageName"] == stage_name, (
        f"the stage must be unchanged after the rejected delete; got {still_there!r}"
    )

    # Positive control: remove the dependent mapping, then the identical delete succeeds.
    apigw.delete_base_path_mapping(domainName=domain_name, basePath="v1")
    from botocore.exceptions import ClientError

    try:
        apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    except ClientError as err:
        raise AssertionError(
            f"the identical DeleteStage call must succeed once the base path mapping is "
            f"removed; got {err.response['Error']['Code']!r}"
        ) from err
    code, message = _client_error(lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading the stage after its delete succeeded, got {code!r}"
    )
    assert message == "Invalid stage identifier specified", message


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


def _create_deployed_api_with_explicit_stage(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
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
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    )
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


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises,
    so an accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NotFoundException", "ResourceNotFoundException",) or
            (exc.response["Error"]["Code"] == "BadRequestException"
             and "Invalid REST API identifier" in exc.response["Error"].get("Message", ""))
        ):
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
