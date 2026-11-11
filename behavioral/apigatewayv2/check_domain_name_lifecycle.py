"""domain-name-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-dn"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainName -> GetDomainName, UpdateDomainName mutates RoutingMode, DeleteDomainName -> NotFoundException."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    apigw = ctx.client("apigatewayv2")
    domain = _domain_name(ctx, "sim2real-dn")
    cert_arn = _self_signed_cert_arn(ctx, domain)

    created = _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))
    assert created["DomainName"] == domain, f"expected echoed DomainName {domain!r}, got {created['DomainName']!r}"

    got = apigw.get_domain_name(DomainName=domain)
    assert got["DomainName"] == domain, f"GetDomainName returned {got['DomainName']!r}, expected {domain!r}"
    assert got.get("Tags") == TAGS, f"expected tags {TAGS!r} on the created domain, got {got.get('Tags')!r}"
    initial_routing_mode = got.get("RoutingMode")

    updated = apigw.update_domain_name(DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING")
    assert updated["RoutingMode"] == "ROUTING_RULE_THEN_API_MAPPING", (
        f"UpdateDomainName response RoutingMode was {updated['RoutingMode']!r}, expected ROUTING_RULE_THEN_API_MAPPING"
    )
    assert updated["RoutingMode"] != initial_routing_mode, (
        f"RoutingMode did not change from its initial value {initial_routing_mode!r}"
    )

    got2 = apigw.get_domain_name(DomainName=domain)
    assert got2["RoutingMode"] == "ROUTING_RULE_THEN_API_MAPPING", (
        f"post-update GetDomainName RoutingMode was {got2['RoutingMode']!r}, expected ROUTING_RULE_THEN_API_MAPPING"
    )
    # the RoutingMode-only update must not disturb unrelated state set at creation
    assert got2.get("Tags") == TAGS, f"tags changed across an unrelated update: {got2.get('Tags')!r} != {TAGS!r}"

    apigw.delete_domain_name(DomainName=domain)
    code, message = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}: {message!r}"
    assert message == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message: {message!r}"
    )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "30", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes, Tags=TAGS_KV)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_outliving_in_use_window(acm, cert_arn))
    return cert_arn


def _delete_cert_outliving_in_use_window(acm, cert_arn: str) -> None:
    """ACM briefly still considers a cert "in use" for a few seconds after the domain name
    that referenced it is deleted, so the first delete attempt can race that window."""
    import time

    for attempt in range(5):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NotFoundException", "ResourceNotFoundException"):
                return
            if code in ("ResourceInUseException", "ThrottlingException", "TooManyRequestsException") and attempt < 4:
                time.sleep(3.0 * (attempt + 1))
                continue
            raise


def _error_code(fn):
    import time

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")


def _retry_throttled(fn, *, attempts: int = 6, base_delay: float = 3.0):
    import time

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < attempts - 1:
                last_exc = exc
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_exc


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
