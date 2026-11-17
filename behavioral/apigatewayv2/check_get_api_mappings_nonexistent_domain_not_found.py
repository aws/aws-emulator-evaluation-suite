"""get-api-mappings-nonexistent-domain-not-found."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-api-mappings-nonexistent-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2", "acm"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _self_signed_certificate(domain: str) -> tuple[bytes, bytes]:
    """A key+cert pair for `domain`, generated locally so no public CA or DNS is involved."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as workdir:
        key_path = os.path.join(workdir, "privkey.pem")
        cert_path = os.path.join(workdir, "fullchain.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "30", "-nodes",
                "-subj", f"/CN={domain}", "-keyout", key_path, "-out", cert_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as fh:
            cert = fh.read()
        with open(key_path, "rb") as fh:
            key = fh.read()
    return cert, key


def _imported_cert_arn(ctx, domain: str) -> str:
    cert, key = _self_signed_certificate(domain)
    acm = ctx.client("acm")
    arn = acm.import_certificate(Certificate=cert, PrivateKey=key)["CertificateArn"]

    def _release():
        for attempt in range(10):
            try:
                acm.delete_certificate(CertificateArn=arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceInUseException" or attempt == 9:
                    raise
                import time

                time.sleep(5)

    ctx.on_cleanup(_release)
    return arn


def _dns_label(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApiMappings against a domain name that does not exist fails NotFoundException, while
    the same call lists a real domain's mapping once one is created."""
    agw = ctx.client("apigatewayv2")

    missing_domain = f"{_dns_label(ctx, 'sim2real-behav-missing')}.example.com"
    code, message = _error(lambda: agw.get_api_mappings(DomainName=missing_domain))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent domain, got {code}: {message!r}"
    )
    assert message == "Invalid domain name identifier specified", (
        f"expected the exact invalid-domain-identifier message, got {message!r}"
    )

    # Positive control: the same operation lists a mapping on a real domain, so the rejection
    # above is about THIS domain name, not about GetApiMappings being universally denied.
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    stage_name = "sim2real"
    agw.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)

    real_domain = f"{_dns_label(ctx, 'sim2real-behav-real')}.example.com"
    cert_arn = _imported_cert_arn(ctx, real_domain)
    agw.create_domain_name(
        DomainName=real_domain,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: agw.delete_domain_name(DomainName=real_domain))

    mapping_id = agw.create_api_mapping(
        ApiId=api_id, DomainName=real_domain, Stage=stage_name, ApiMappingKey="v1"
    )["ApiMappingId"]

    items = agw.get_api_mappings(DomainName=real_domain)["Items"]
    assert any(item["ApiMappingId"] == mapping_id for item in items), (
        f"expected mapping {mapping_id!r} for {real_domain!r} in GetApiMappings, "
        f"got {[i['ApiMappingId'] for i in items]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
