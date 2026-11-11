"""domain-api-association-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-api-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainName rejects an imported certificate ("Certificate is invalid."),
    so the domain is absent from GetDomainName/ListDomainNames and AssociateApi on it 404s; a
    GraphQL API created alongside is the positive control."""
    appsync = ctx.client("appsync")

    domain = _domain_string(ctx)
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_domain_name(domainName=domain)))
    cert_arn = _issue_self_signed_cert(ctx, domain)

    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-gapi-"), authenticationType="API_KEY"
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=api_id)))
    assert api_id, "positive control failed: CreateGraphqlApi returned no apiId"

    code, message = _create_domain_name_expect_rejection(appsync, domainName=domain, certificateArn=cert_arn)
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message}"
    assert message == "Certificate is invalid.", (
        f"expected a certificate-provenance rejection, got {code}: {message}"
    )

    got = _error(lambda: appsync.get_domain_name(domainName=domain))
    assert got == ("NotFoundException", "Domain name not found"), (
        f"GetDomainName should 404 -- CreateDomainName never succeeded; got {got!r}"
    )
    configs = _list_all_domain_name_configs(appsync)
    assert domain not in {c["domainName"] for c in configs}, (
        f"{domain} appears in ListDomainNames despite CreateDomainName having been rejected"
    )

    assoc = _error(lambda: appsync.associate_api(domainName=domain, apiId=api_id))
    assert assoc == ("NotFoundException", "Domain name not found."), (
        f"AssociateApi against a domain that was never created should 404, got {assoc!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _domain_string(ctx) -> str:
    # CreateDomainName rejects RFC 2606 reserved domains (example.com/.net/.org, .test, .invalid,
    # .localhost) with "Invalid domain name", so use a made-up ".com" name.
    base = ctx.unique_name("sim2real-appsync-assoc-").rstrip("-").lower()
    return f"{base}.com"


def _create_domain_name_expect_rejection(appsync, *, timeout_s: float = 80, interval_s: float = 10, **kwargs):
    """Retry a certificate or throttling rejection within a bounded window, then return it as
    (code, message). Certificate propagation and the low TPS quota can produce the same error
    transiently; the rejection persists past the window. An unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appsync.create_domain_name(**kwargs)
            raise AssertionError(
                "CreateDomainName unexpectedly SUCCEEDED with a self-signed-provenance "
                "certificate -- this check's premise needs re-verifying against real AWS"
            )
        except ClientError as exc:
            err = exc.response["Error"]
            code = err.get("Code")
            message = err.get("Message", "")
            transient = code == "TooManyRequestsException" or (
                code == "BadRequestException" and "certificate" in message.lower()
            )
            if not transient or time.monotonic() >= deadline:
                return code, message
            time.sleep(interval_s)


def _list_all_domain_name_configs(appsync):
    configs = []
    kwargs: dict = {}
    while True:
        resp = appsync.list_domain_names(**kwargs)
        configs.extend(resp.get("domainNameConfigs", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return configs
        kwargs = {"nextToken": next_token}


def _acm_client_in_us_east_1(ctx):
    """AppSync's custom-domain feature requires the certificateArn to be issued/imported
    in us-east-1 specifically, regardless of which region the AppSync API itself lives in."""
    return ctx.client("acm", region="us-east-1")


def _issue_self_signed_cert(ctx, domain_name: str) -> str:
    """Import into ACM a leaf signed by a throwaway root CA (not a bare self-signed leaf): the
    best-formed imported certificate possible without owning the domain."""
    import subprocess
    import tempfile


    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = _acm_client_in_us_east_1(ctx)
    with tempfile.TemporaryDirectory() as tmp:
        ca_key_path = f"{tmp}/ca-key.pem"
        ca_cert_path = f"{tmp}/ca-cert.pem"
        leaf_key_path = f"{tmp}/leaf-key.pem"
        leaf_csr_path = f"{tmp}/leaf.csr"
        leaf_cert_path = f"{tmp}/leaf-cert.pem"
        ext_path = f"{tmp}/leaf-ext.cnf"

        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", ca_key_path, "-out", ca_cert_path,
                "-days", "3650", "-subj", "/CN=sim2real-behav-appsync-test-root-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always,issuer:always",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
                "-keyout", leaf_key_path, "-out", leaf_csr_path,
                "-subj", f"/CN={domain_name}",
            ],
            check=True,
            capture_output=True,
        )

        with open(ext_path, "w") as fh:
            fh.write(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName=DNS:{domain_name}\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n"
            )

        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", leaf_csr_path,
                "-CA", ca_cert_path, "-CAkey", ca_key_path, "-CAcreateserial",
                "-out", leaf_cert_path, "-days", "365",
                "-extfile", ext_path,
            ],
            check=True,
            capture_output=True,
        )

        with open(leaf_key_path, "rb") as fh:
            key_bytes = fh.read()
        with open(leaf_cert_path, "rb") as fh:
            cert_bytes = fh.read()
        with open(ca_cert_path, "rb") as fh:
            chain_bytes = fh.read()

    cert_name = ctx.unique_name("sim2real-behav-appsync-cert-")
    arn = acm.import_certificate(
        Certificate=cert_bytes,
        PrivateKey=key_bytes,
        CertificateChain=chain_bytes,
        Tags=[{"Key": "Name", "Value": cert_name}],
    )["CertificateArn"]

    def _cleanup():
        # A just-refused CreateDomainName holds the certificate in use for a while; wait it out,
        # bounded, so a leaked certificate still fails the teardown.
        deadline = time.monotonic() + 300.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(10.0)

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
