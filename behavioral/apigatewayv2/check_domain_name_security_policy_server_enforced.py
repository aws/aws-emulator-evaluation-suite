"""domain-name-security-policy-server-enforced."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-security-policy-server-enforced"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The minimum TLS security policy set on a domain name's configuration is enforced and
    reported consistently by GetDomainName, both at creation and after an UpdateDomainName."""
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-secpol-").lower().replace("_", "-")
    domain_name = f"{label}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)

    _create_domain_name_with_retry(
        ctx,
        domain_name,
        [{"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}],
        resource_tags={"phase": "secpol-check"},
    )
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=domain_name))

    created = apigwv2.get_domain_name(DomainName=domain_name)
    configs = created["DomainNameConfigurations"]
    assert len(configs) == 1, f"expected exactly 1 DomainNameConfiguration, got {len(configs)}"
    assert configs[0]["SecurityPolicy"] == "TLS_1_2", (
        f"expected SecurityPolicy TLS_1_2 right after create, got {configs[0]['SecurityPolicy']!r}"
    )

    # TLS_1_0 is a documented enum value for SecurityPolicy, but real AWS enforces TLS_1_2
    # as the floor for APIGatewayV2 domain names and rejects any attempt to downgrade below it.
    # Assert that enforcement, and that GetDomainName still reflects the untouched TLS_1_2 state.
    code, message = _error(
        lambda: apigwv2.update_domain_name(
            DomainName=domain_name,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_0"}
            ],
        )
    )
    assert code == "BadRequestException", (
        f"expected UpdateDomainName to reject a TLS_1_0 downgrade with BadRequestException, got {code!r}: {message!r}"
    )
    assert message == "TLS_1_0 is not supported for APIGatewayV2 domainName.", (
        f"expected the exact TLS_1_0 refusal message, got {message!r}"
    )

    unchanged = apigwv2.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"]
    assert unchanged[0]["SecurityPolicy"] == "TLS_1_2", (
        "expected the rejected downgrade to leave SecurityPolicy at TLS_1_2, "
        f"got {unchanged[0]['SecurityPolicy']!r}"
    )

    # positive control: re-asserting the same (valid) security policy via UpdateDomainName still
    # succeeds and GetDomainName consistently reflects the enforced policy afterward.
    apigwv2.update_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
    )
    final_policy = _poll_until_security_policy(ctx, domain_name, "TLS_1_2", timeout_s=180)
    recheck = apigwv2.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"][0]["SecurityPolicy"]
    assert final_policy == recheck == "TLS_1_2", (
        "expected two independent reads after the positive-control update to both show TLS_1_2, "
        f"got {final_policy!r} then {recheck!r}"
    )


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _import_self_signed_cert(ctx, common_name):
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "phase", "Value": "secpol-check"}]
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


def _delete_certificate_when_released(acm, cert_arn, timeout_s=300.0, interval_s=10.0):
    # The certificate stays in use for a while after DeleteDomainName returns; retry until
    # ACM releases it.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until_security_policy(ctx, domain_name, expected_policy, timeout_s=180.0, interval_s=5.0):
    apigwv2 = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    last_policy = None
    while time.monotonic() < deadline:
        configs = apigwv2.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"]
        last_policy = configs[0].get("SecurityPolicy") if configs else None
        if last_policy == expected_policy:
            return last_policy
        time.sleep(interval_s)
    raise AssertionError(
        f"SecurityPolicy never converged to {expected_policy!r} within {timeout_s}s; "
        f"last observed {last_policy!r}"
    )


def _create_domain_name_with_retry(
    ctx, domain_name, configs, timeout_s=180.0, interval_s=10.0, resource_tags=None
):
    # CreateDomainName can be throttled (TooManyRequestsException) shortly after an ACM
    # certificate import while the account-level quota catches up; retry with backoff.
    apigwv2 = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = {"DomainName": domain_name, "DomainNameConfigurations": configs}
    if resource_tags:
        kwargs["Tags"] = resource_tags
    while time.monotonic() < deadline:
        try:
            return apigwv2.create_domain_name(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "TooManyRequestsException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"CreateDomainName still throttled after {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
