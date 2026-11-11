"""create-domain-configuration-invalid-certificate-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "create-domain-configuration-invalid-certificate-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]

_UNTRUSTED = (
    "Must provide validation certificate when using server certificates not signed by "
    "trusted CA or not within"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainConfiguration with a server certificate not signed by a trusted CA is rejected
    with InvalidRequestException, whether or not the certificate's SAN covers the domain."""
    require_tools("openssl")
    acm = ctx.client("acm")
    iot = ctx.client("iot")

    cert_domain = ctx.unique_name("sim2real-domcfg-cert-").replace("_", "-") + ".example.com"
    other_domain = ctx.unique_name("sim2real-domcfg-other-").replace("_", "-") + ".example.com"
    cert_pem, key_pem = _generate_self_signed(cert_domain)
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    acm.add_tags_to_certificate(CertificateArn=cert_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])

    # The trust-chain precondition fires before, and independent of, any SAN coverage check,
    # and no certificate obtainable without owning a real domain passes it; so the domain is
    # varied (matching, then not) to show the rejection is identical either way.
    matched_config = ctx.unique_name("sim2real-domcfg-matched-")
    err_matched = _error(
        lambda: iot.create_domain_configuration(
            domainConfigurationName=matched_config,
            domainName=cert_domain,
            serverCertificateArns=[cert_arn],
            serviceType="DATA",
        )
    )
    assert err_matched == ("InvalidRequestException", _UNTRUSTED), err_matched
    err_matched_after = _error(
        lambda: iot.describe_domain_configuration(domainConfigurationName=matched_config)
    )
    assert err_matched_after == ("ResourceNotFoundException", _not_found(ctx, matched_config)), err_matched_after

    # identical rejection with the same certificate and a domain it does NOT cover --
    # proving domain/SAN match is not the operative rule here
    bad_config = ctx.unique_name("sim2real-domcfg-bad-")
    err_bad = _error(
        lambda: iot.create_domain_configuration(
            domainConfigurationName=bad_config,
            domainName=other_domain,
            serverCertificateArns=[cert_arn],
            serviceType="DATA",
        )
    )
    assert err_bad == ("InvalidRequestException", _UNTRUSTED), err_bad
    err_bad_after = _error(
        lambda: iot.describe_domain_configuration(domainConfigurationName=bad_config)
    )
    assert err_bad_after == ("ResourceNotFoundException", _not_found(ctx, bad_config)), err_bad_after

    # positive control: the account's AWS-managed data endpoint and its domain
    # configurations read back, so the principal is healthy for IoT domain operations.
    # Creating an AWS-managed domain configuration is not used here: AWS requires it to
    # stay disabled for 7 days before it can be deleted, so a run could not tear it down.
    assert iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    names = [
        d["domainConfigurationName"]
        for d in iot.list_domain_configurations()["domainConfigurations"]
    ]
    assert matched_config not in names and bad_config not in names, names


def _run(cmd: list) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")


def _generate_self_signed(common_name: str):
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        crt_path = os.path.join(d, "cert.pem")
        _run(["openssl", "genrsa", "-out", key_path, "2048"])
        _run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-key", key_path,
                "-sha256", "-days", "30", "-subj", f"/CN={common_name}", "-out", crt_path,
                "-addext", f"subjectAltName=DNS:{common_name}",
                "-addext", "extendedKeyUsage=serverAuth",
            ]
        )
        with open(crt_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    return cert_pem, key_pem


def _not_found(ctx, config_name: str) -> str:
    return (
        "Could not find domain configuration for given account ID and domain configuration "
        f"name, AccountId: {ctx.account}, DomainConfigurationName: {config_name}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
