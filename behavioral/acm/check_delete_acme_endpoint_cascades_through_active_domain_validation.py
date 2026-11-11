"""delete-acme-endpoint-cascades-through-active-domain-validation."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-cascades-through-active-domain-validation"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeEndpoint with an active domain validation attached succeeds (no
    ConflictException), and the endpoint and its domain validation are both gone afterward
    (ResourceNotFoundException) rather than the child being left orphaned."""
    acm = ctx.client("acm")
    _require_acme_api(acm)

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)

    domain_name = f"{uuid.uuid4().hex[:10]}.sim2real.example"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
    )["AcmeDomainValidationArn"]
    dv_deleted = [False]
    ctx.on_cleanup(
        lambda: None
        if dv_deleted[0]
        else acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    )

    # Sanity: the domain validation is live and attached before we touch the endpoint.
    dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert dv["AcmeEndpointArn"] == endpoint_arn, (
        f"expected domain validation to be attached to {endpoint_arn!r}, got {dv['AcmeEndpointArn']!r}"
    )

    # Delete the endpoint while the domain validation is still attached -- this must succeed,
    # not be rejected, per the documented cascade-delete contract.
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)

    # Real consequence #1: the endpoint itself is actually gone (bounded poll, not merely a
    # 200 that leaves the resource in a lingering DELETING state).
    _poll_until(
        lambda: _gone(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)),
        lambda gone: gone is True,
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Real consequence #2: the cascade actually removed the child domain validation too --
    # not left as an orphaned record pointing at a deleted endpoint.
    _poll_until(
        lambda: _gone(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)),
        lambda gone: gone is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    dv_deleted[0] = True


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/CreateAcmeDomainValidation/DeleteAcmeEndpoint) -- upgrade "
            "botocore/boto3 to a version that models the ACM ACME endpoint API surface"
        )


def _gone(fn):
    """True once fn() is refused with ResourceNotFoundException, False while it still reads."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


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
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup_endpoint():
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
