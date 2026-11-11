"""acme-domain-validation-punycode-domain-persists."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-punycode-domain-persists"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An internationalized (punycode, xn--) domain name supplied to CreateAcmeDomainValidation
    must be stored and echoed back byte-for-byte by DescribeAcmeDomainValidation -- not
    lowercased differently, IDNA-decoded to Unicode, or otherwise normalized/mutated."""
    acm = ctx.client("acm")
    _require_acme_api(acm)

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)

    punycode_label = "xn--" + uuid.uuid4().hex[:10]
    domain_name = f"{punycode_label}.sim2real.example"

    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-acmedv-")}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert dv["DomainName"] == domain_name, f"expected {domain_name!r}, got {dv['DomainName']!r}"


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/CreateAcmeDomainValidation/DescribeAcmeDomainValidation) -- "
            "upgrade botocore/boto3 to a version that models the ACM ACME endpoint API surface"
        )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_acme_endpoint(ctx, acm) -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup_endpoint():
        deadline = time.monotonic() + 30.0
        while True:
            try:
                acm.delete_acme_endpoint(AcmeEndpointArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException" and time.monotonic() < deadline:
                    time.sleep(2)
                    continue
                raise

    ctx.on_cleanup(_cleanup_endpoint)
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"ACME endpoint entered {status}, expected ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
