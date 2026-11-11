"""list-acme-domain-validations-reflects-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-acme-domain-validations-reflects-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAcmeDomainValidations includes a freshly created domain validation and
    excludes it after DeleteAcmeDomainValidation."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    domain = _unique_domain(ctx, "dvlist")

    create_resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-dvlist-")}],
    )
    dv_arn = create_resp["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_dv_ignore_errors(ctx, dv_arn))

    arns_after_create = _list_all_domain_validation_arns(ctx, endpoint_arn)
    assert dv_arn in arns_after_create, "new domain validation missing from ListAcmeDomainValidations"

    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)

    deadline = time.monotonic() + 90.0
    while True:
        arns_now = _list_all_domain_validation_arns(ctx, endpoint_arn)
        if dv_arn not in arns_now:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"{dv_arn} still present in ListAcmeDomainValidations after deletion")
        time.sleep(3.0)

    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)


def _unique_domain(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower().replace("_", "-").strip("-")
    return f"{raw}.example.com"


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-dvlist-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _delete_dv_ignore_errors(ctx, dv_arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)


def _list_all_domain_validation_arns(ctx, endpoint_arn: str) -> list[str]:
    acm = ctx.client("acm")
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_domain_validations(**kwargs)
        arns.extend(d["AcmeDomainValidationArn"] for d in resp.get("AcmeDomainValidations", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
