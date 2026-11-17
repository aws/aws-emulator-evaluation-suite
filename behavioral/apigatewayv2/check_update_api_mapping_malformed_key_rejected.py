"""update-api-mapping-malformed-key-rejected."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-api-mapping-malformed-key-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2", "acm"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-apigwv2"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApiMapping with an ApiMappingKey that starts with '/' is rejected with
    BadRequestException, leaving the mapping's key unchanged; a well-formed key still applies.
    """
    apigwv2 = ctx.client("apigatewayv2")
    host = _mint_regional_domain(ctx)
    api_id = _mint_http_api(ctx)
    _mint_stage(ctx, api_id, "dev")

    created = apigwv2.create_api_mapping(
        DomainName=host, ApiId=api_id, Stage="dev", ApiMappingKey="original-path"
    )
    mapping_id = created["ApiMappingId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api_mapping(DomainName=host, ApiMappingId=mapping_id))

    code, message = _refusal(
        lambda: apigwv2.update_api_mapping(
            DomainName=host, ApiMappingId=mapping_id, ApiId=api_id,
            ApiMappingKey="/bad-leading-slash",
        )
    )
    assert code == "BadRequestException", (
        f"a leading-slash ApiMappingKey should be rejected with BadRequestException, got {code!r}"
    )
    expected_message = "API mapping key should not start with a '/' or have consecutive '/'s."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    unchanged = apigwv2.get_api_mapping(DomainName=host, ApiMappingId=mapping_id)
    assert unchanged["ApiMappingKey"] == "original-path", (
        f"the refused UpdateApiMapping must leave the key unchanged, got "
        f"{unchanged.get('ApiMappingKey')!r}"
    )

    # positive control: a syntactically valid key still updates successfully.
    updated = apigwv2.update_api_mapping(
        DomainName=host, ApiMappingId=mapping_id, ApiId=api_id, ApiMappingKey="good-path"
    )
    assert updated["ApiMappingKey"] == "good-path", (
        f"a syntactically valid key must update, got ApiMappingKey={updated.get('ApiMappingKey')!r}"
    )
    confirmed = apigwv2.get_api_mapping(DomainName=host, ApiMappingId=mapping_id)
    assert confirmed["ApiMappingKey"] == "good-path", (
        f"independent read after the accepted UpdateApiMapping must show the new key, "
        f"got {confirmed.get('ApiMappingKey')!r}"
    )


def _refusal(fn):
    """The (code, message) of fn()'s ClientError; a throttle is absorbed, success raises."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            return code, error.get("Message")
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


def _mint_regional_domain(ctx) -> str:
    """A REGIONAL custom domain backed by a throwaway self-signed certificate."""
    apigwv2 = ctx.client("apigatewayv2")
    host = ctx.unique_name("sim2real-apigwv2").lower().replace("_", "-") + ".example.com"
    cert_arn = _mint_self_signed_cert(ctx, host)
    _past_api_gateway_throttle(lambda: apigwv2.create_domain_name(
        DomainName=host,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
        Tags=TAGS,
    ))
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=host))
    return host


def _past_api_gateway_throttle(fn, *, deadline_s: float = 60.0):
    """CreateDomainName is rate-limited per account; wait it out rather than call it a fidelity
    failure."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException"):
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(4.0)


def _mint_self_signed_cert(ctx, host: str) -> str:
    """Generate an RSA key/cert pair with openssl and import it into ACM for ``host``."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    workdir = tempfile.mkdtemp()
    try:
        key_path = Path(workdir, "key.pem")
        cert_path = Path(workdir, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-nodes", "-x509", "-newkey", "rsa:2048", "-days", "365",
             "-subj", f"/CN={host}", "-keyout", str(key_path), "-out", str(cert_path)],
            check=True, capture_output=True, env=ctx.subprocess_env(),
        )
        acm = ctx.client("acm")
        cert_arn = acm.import_certificate(
            Certificate=cert_path.read_bytes(),
            PrivateKey=key_path.read_bytes(),
            Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
        )["CertificateArn"]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    ctx.on_cleanup(lambda: _retire_cert(acm, cert_arn))
    return cert_arn


def _retire_cert(acm, cert_arn: str) -> None:
    """ACM keeps answering DeleteCertificate with ResourceInUseException for a short while after
    the domain name referencing it is gone; poll the delete to a deadline rather than leak it."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _mint_http_api(ctx) -> str:
    apigwv2 = ctx.client("apigatewayv2")
    api_id = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))
    return api_id


def _mint_stage(ctx, api_id: str, stage_name: str) -> None:
    apigwv2 = ctx.client("apigatewayv2")
    apigwv2.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)
    ctx.on_cleanup(lambda: apigwv2.delete_stage(ApiId=api_id, StageName=stage_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
