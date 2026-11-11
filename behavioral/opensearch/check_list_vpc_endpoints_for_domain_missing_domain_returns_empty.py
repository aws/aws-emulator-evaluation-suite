"""list-vpc-endpoints-for-domain-missing-domain-returns-empty."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vpc-endpoints-for-domain-missing-domain-returns-empty"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListVpcEndpointsForDomain answers a nonexistent DomainName with 200 and an empty
    VpcEndpointSummaryList, while DescribeDomain rejects the same name with ResourceNotFoundException.
    """
    os_client = ctx.client("opensearch")

    missing_domain_name = _short_name(ctx, "sim2real-vpce-none-")
    existing = {d["DomainName"] for d in os_client.list_domain_names().get("DomainNames", [])}
    assert missing_domain_name not in existing, (
        f"precondition: {missing_domain_name} must not exist; ListDomainNames reports {sorted(existing)!r}"
    )

    resp = os_client.list_vpc_endpoints_for_domain(DomainName=missing_domain_name)
    assert resp["VpcEndpointSummaryList"] == [], (
        "expected a successful empty VpcEndpointSummaryList for a nonexistent domain, got "
        f"{resp['VpcEndpointSummaryList']!r}"
    )

    describe_code, describe_message = _error_code(
        lambda: os_client.describe_domain(DomainName=missing_domain_name)
    )
    assert describe_code == "ResourceNotFoundException", (
        "the same nonexistent domain must still be a hard ResourceNotFoundException for "
        f"DescribeDomain -- otherwise the empty list above proves nothing -- got {describe_code}"
    )
    assert describe_message == f"Domain not found: {missing_domain_name}", (
        f"DescribeDomain not-found message {describe_message!r}"
    )



def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _short_name(ctx, prefix, max_len=28):
    name = ctx.unique_name(prefix)[:max_len]
    if not name[-1].isalnum():
        name = name[:-1] + "0"
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
