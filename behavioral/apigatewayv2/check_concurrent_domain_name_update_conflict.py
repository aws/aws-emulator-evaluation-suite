"""concurrent-domain-name-update-conflict."""
from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-domain-name-update-conflict"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateDomainName calls with different RoutingMode values settle on one writer's
    value, never a state matching neither, and the domain stays readable and updatable afterward."""
    apigw = ctx.client("apigatewayv2")

    domain = _domain_name(ctx, "sim2real-behav-domconc")
    cert_arn = _self_signed_cert_arn(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            RoutingMode="API_MAPPING_ONLY",
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))

    def _update_a():
        return _retry_throttled(
            lambda: apigw.update_domain_name(DomainName=domain, RoutingMode="ROUTING_RULE_ONLY")
        )

    def _update_b():
        return _retry_throttled(
            lambda: apigw.update_domain_name(
                DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING"
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(_update_a)
        fut2 = pool.submit(_update_b)
        outcome1 = _outcome(fut1)
        outcome2 = _outcome(fut2)

    successes = [o for o in (outcome1, outcome2) if o[0] == "ok"]
    assert len(successes) >= 1, f"expected at least one writer to succeed, got {(outcome1, outcome2)!r}"

    # Effect present but consistent (no split-brain / lost update / corruption): the final
    # RoutingMode observed via GetDomainName matches exactly one of the two attempted writes.
    final = apigw.get_domain_name(DomainName=domain)
    assert final["RoutingMode"] in ("ROUTING_RULE_ONLY", "ROUTING_RULE_THEN_API_MAPPING"), (
        f"unexpected final RoutingMode {final['RoutingMode']!r}"
    )

    # Positive control: the domain remains normally updatable afterward.
    updated = _retry_throttled(
        lambda: apigw.update_domain_name(DomainName=domain, RoutingMode="API_MAPPING_ONLY")
    )
    assert updated["RoutingMode"] == "API_MAPPING_ONLY", (
        f"expected domain to remain normally updatable after the race, "
        f"got RoutingMode {updated['RoutingMode']!r}"
    )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

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
    ctx.on_cleanup(lambda: _delete_cert_after_unlink(acm, cert_arn))
    return cert_arn


def _delete_cert_after_unlink(acm, cert_arn: str) -> None:
    """ACM refuses the delete for a few seconds after the domain name that referenced the cert
    is deleted: retry ResourceInUseException every 2 s to a 45 s deadline, then raise."""
    import time

    deadline = time.monotonic() + 45
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


def _outcome(future):
    try:
        future.result()
        return ("ok", None)
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])


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
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
