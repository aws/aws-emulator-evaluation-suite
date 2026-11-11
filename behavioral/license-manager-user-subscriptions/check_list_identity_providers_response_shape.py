"""list-identity-providers-response-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identity-providers-response-shape"
GROUP = "control-plane"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentityProviders returns a well-typed, paginated response even when the
    account has no (or few) registered identity providers -- every summary entry must
    carry the documented identity/status/ARN fields, not a partial or malformed shape."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    resp = lmus.list_identity_providers(MaxResults=10)
    assert "IdentityProviderSummaries" in resp, f"response missing IdentityProviderSummaries: {resp!r}"
    summaries = resp["IdentityProviderSummaries"]
    assert isinstance(summaries, list), f"IdentityProviderSummaries is {type(summaries).__name__}, expected list"
    for summary in summaries:
        assert "IdentityProvider" in summary, f"summary missing IdentityProvider: {summary!r}"
        assert "Product" in summary and isinstance(summary["Product"], str), (
            f"summary Product is {summary.get('Product')!r}, expected a str"
        )
        assert "Status" in summary and isinstance(summary["Status"], str), (
            f"summary Status is {summary.get('Status')!r}, expected a str"
        )
        assert "IdentityProviderArn" in summary and summary["IdentityProviderArn"].startswith("arn:"), (
            f"summary IdentityProviderArn is {summary.get('IdentityProviderArn')!r}, expected an arn: string"
        )
    if "NextToken" in resp:
        assert isinstance(resp["NextToken"], str), f"NextToken is {type(resp['NextToken']).__name__}, expected str"


def _ensure_slr(ctx):
    """license-manager-user-subscriptions API calls require the
    AWSServiceRoleForAWSLicenseManagerUserSubscriptionsService service-linked role to
    exist in the account; without it every call is rejected with
    AccessDeniedException("Service Linked role is not present") before the service
    ever evaluates the request. Create it idempotently, then poll a cheap real call
    until the role has actually propagated -- IAM's eventual consistency means the
    license-manager-user-subscriptions API can still see the role as absent for a
    few seconds right after CreateServiceLinkedRole returns."""
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="license-manager-user-subscriptions.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise

    lmus_probe = ctx.client("license-manager-user-subscriptions")
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            lmus_probe.list_instances(MaxResults=1)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException" and "Service Linked role" in str(exc):
                time.sleep(3.0)
                continue
            return


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
