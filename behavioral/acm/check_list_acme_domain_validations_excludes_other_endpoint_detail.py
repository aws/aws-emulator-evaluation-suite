"""list-acme-domain-validations-excludes-other-endpoint-detail."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-acme-domain-validations-excludes-other-endpoint-detail"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAcmeDomainValidations for one endpoint lists its own validation and never one that
    belongs to a sibling endpoint of the same caller."""
    acm = ctx.client("acm")

    endpoint_a = _create_active_endpoint(ctx, acm, "dv-siblings-a", contact="NOT_REQUIRED")
    endpoint_b = _create_active_endpoint(ctx, acm, "dv-siblings-b", contact="NOT_REQUIRED")

    domain_a = _domain_name(ctx, "dv-siblings-a")
    domain_b = _domain_name(ctx, "dv-siblings-b")

    dv_a_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_a,
        DomainName=domain_a,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "Name", "Value": domain_a}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_a_arn)))

    dv_b_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_b,
        DomainName=domain_b,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "Name", "Value": domain_b}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_b_arn)))

    list_a = _list_domain_validations(acm, endpoint_a)
    arns_a = {v["AcmeDomainValidationArn"] for v in list_a}
    domains_a = {v["DomainName"] for v in list_a}
    assert dv_a_arn in arns_a, f"endpoint A's own validation is missing from its own listing: {arns_a}"
    assert dv_b_arn not in arns_a, f"sibling endpoint B's validation leaked into endpoint A's listing: {arns_a}"
    assert domain_b not in domains_a, f"sibling endpoint B's domain leaked into endpoint A's listing: {domains_a}"

    # positive control: endpoint B's listing symmetrically shows only its own validation
    list_b = _list_domain_validations(acm, endpoint_b)
    arns_b = {v["AcmeDomainValidationArn"] for v in list_b}
    assert dv_b_arn in arns_b, f"endpoint B's own validation is missing from its own listing: {arns_b}"
    assert dv_a_arn not in arns_b, f"sibling endpoint A's validation leaked into endpoint B's listing: {arns_b}"



def _delete_if_present(fn):
    """Teardown delete: return once it succeeds or the resource is already gone, retry a
    ConflictException while a dependent resource is still being released, raise the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _domain_name(ctx, label: str) -> str:
    token = ctx.unique_name(f"sim2real-{label}-").lower().strip("-")
    return f"{token}.example.com"


def _create_active_endpoint(ctx, acm, label: str, contact: str | None = None) -> str:
    name = ctx.unique_name(f"sim2real-{label}-")
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": name}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(
    acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _list_domain_validations(acm, endpoint_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_domain_validations(**kwargs)
        out.extend(resp.get("AcmeDomainValidations", []))
        token = resp.get("NextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
