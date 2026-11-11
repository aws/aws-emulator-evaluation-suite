"""domain-name-api-association-lifecycle."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "domain-name-api-association-lifecycle"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainName rejects an imported (not ACM-validated) certificate with "Certificate is
    invalid." and the domain name is never created; the certificate and a GraphQL API are controls.
    AssociateApi needs an ACM-issued certificate for an owned domain, so it is not exercised."""

    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    appsync = ctx.client("appsync")
    # CreateDomainName rejects RFC 2606 reserved domains (example.com/.net/.org) with
    # "Invalid domain name", so use a non-reserved placeholder suffix.
    domain = f"{ctx.unique_name('sim2real-behav-')}.example-test.com".lower()
    cert_arn = _create_self_signed_acm_cert(ctx, domain)
    # Registered before the (expected-to-fail) create attempt: if CreateDomainName ever
    # unexpectedly succeeds, this still tears the domain name down.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_domain_name(domainName=domain)))

    # Positive control 1/2: the imported certificate itself is well-formed and ACM serves it —
    # isolates the refusal below to AppSync's own cross-service check, not a broken certificate.
    acm = _acm_domain_cert_client(ctx)
    cert_status = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["Status"]
    assert cert_status == "ISSUED", f"imported certificate never reached ISSUED, got {cert_status}"

    # Positive control 2/2: AppSync access and GraphQL API creation are otherwise healthy.
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=api_id)))
    fetched_api = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched_api["apiId"] == api_id, "GetGraphqlApi does not reflect the just-created api"

    code, message = _create_domain_name_expect_refused(appsync, domain, cert_arn)
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message}"
    assert message == "Certificate is invalid.", (
        f"expected the exact BadRequestException message AWS returns, got {message!r}"
    )
    assert "certificate is invalid" in message.lower(), (
        f"expected the certificate-provenance refusal, got a different BadRequestException: {message}"
    )

    # Effect-absent, via two independent reads: CreateDomainName's refusal must mean the domain
    # name was never created, not merely that the call returned an error.
    listed = {
        cfg["domainName"] for cfg in appsync.list_domain_names().get("domainNameConfigs", [])
    }
    assert domain not in listed, "ListDomainNames shows a domain that CreateDomainName refused to create"
    get_code, get_message = _error_code(lambda: appsync.get_domain_name(domainName=domain))
    assert get_code == "NotFoundException", f"GetDomainName should 404 for a never-created domain, got {get_code}"
    assert get_message == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns, got {get_message!r}"
    )



def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_domain_name_expect_refused(appsync, domain: str, cert_arn: str, timeout_s: float = 45.0):
    """Return CreateDomainName's terminal (code, message), retrying only the account-level throttle
    within a bounded window; the certificate rejection does not clear with retrying.
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            appsync.create_domain_name(
                domainName=domain,
                certificateArn=cert_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "TooManyRequestsException" and time.monotonic() < deadline:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            return code, message
        else:
            raise AssertionError(
                "CreateDomainName ACCEPTED an ImportCertificate-sourced certificate for "
                f"domainName={domain!r} — real AWS has been observed to reject this "
                "unconditionally; this target's certificate-provenance check diverges from AWS"
            )


def _acm_domain_cert_client(ctx):
    """AppSync custom domains take an ACM certificate from us-east-1 only (they are
    CloudFront-backed), whatever the API's region."""
    from botocore.config import Config

    return ctx.client(
        "acm",
        region="us-east-1",
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )


def _create_self_signed_acm_cert(ctx, common_name: str) -> str:
    """Import into ACM a leaf signed by a fresh local CA, with the CA as CertificateChain.

    AppSync rejects a bare self-signed leaf outright, so the leaf's issuer must differ from it."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        ca_key_path = tmp_path / "ca-key.pem"
        ca_cert_path = tmp_path / "ca-cert.pem"
        key_path = tmp_path / "key.pem"
        csr_path = tmp_path / "csr.pem"
        cert_path = tmp_path / "cert.pem"
        ext_path = tmp_path / "leaf-ext.cnf"

        # A self-signed root CA — self-signed is fine for a CA, only a self-signed leaf is
        # rejected by AppSync's domain certificate validation.
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(ca_key_path), "-out", str(ca_cert_path),
                "-days", "30", "-subj", "/CN=sim2real-test-root-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(csr_path),
                "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        ext_path.write_text(
            f"subjectAltName=DNS:{common_name}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        # Sign the leaf with the CA -> issuer (CA) != subject (leaf), i.e. NOT self-signed.
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", str(csr_path),
                "-CA", str(ca_cert_path), "-CAkey", str(ca_key_path), "-CAcreateserial",
                "-out", str(cert_path), "-days", "30", "-extfile", str(ext_path),
            ],
            check=True, capture_output=True,
        )
        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()
        chain_pem = ca_cert_path.read_bytes()
    acm = _acm_domain_cert_client(ctx)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        CertificateChain=chain_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_cert_when_released(acm, cert_arn)))
    return cert_arn


# budget.cleanup_timeout for behavioral/appsync
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    domain name as a user, up to the cleanup budget; any other error raises."""
    from botocore.exceptions import ClientError

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
