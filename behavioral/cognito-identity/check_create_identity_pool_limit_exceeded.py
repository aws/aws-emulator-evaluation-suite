"""create-identity-pool-limit-exceeded."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-pool-limit-exceeded"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _discover_providers_per_pool_quota(ctx) -> int:
    """Read the account's actual "Amazon Cognito user pool providers per identity pool" quota via
    Service Quotas. The quota is documented as adjustable (default 50, raisable to 1000), so pinning
    50 would flake against any account whose quota was raised."""
    sq = ctx.client("service-quotas")
    for lister in ("list_service_quotas", "list_aws_default_service_quotas"):
        try:
            paginator = sq.get_paginator(lister)
            for page in paginator.paginate(ServiceCode="cognito-identity"):
                for quota in page.get("Quotas", []):
                    if "user pool providers per identity pool" in quota.get("QuotaName", "").lower():
                        return int(quota["Value"])
        except ClientError:
            continue
    raise AssertionError(
        "could not discover the cognito-identity user-pool-providers-per-identity-pool quota via "
        "Service Quotas (ServiceCode='cognito-identity')"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool with one more CognitoIdentityProviders entry than the discovered quota fails with
    LimitExceededException and its exact message, while exactly the quota is accepted and DescribeIdentityPool
    returns all of them.
    """
    ev = ctx.client("cognito-identity")
    quota = _discover_providers_per_pool_quota(ctx)
    over_limit_providers = [
        {
            "ProviderName": f"cognito-idp.{ctx.region}.amazonaws.com/{ctx.region}_fake{i:05d}",
            "ClientId": f"sim2real_behav_client_{uuid.uuid4().hex}",
        }
        for i in range(quota + 1)
    ]
    over_pool_id = None
    try:
        resp = ev.create_identity_pool(
            IdentityPoolName=f"sim2real-behav-pool-over-quota-{uuid.uuid4().hex[:8]}".replace("-", "_"),
            AllowUnauthenticatedIdentities=True,
            CognitoIdentityProviders=over_limit_providers,
            IdentityPoolTags={"sim2real": CHECK},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        over_pool_id = resp["IdentityPoolId"]
        ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=over_pool_id))
        raise AssertionError(
            f"expected LimitExceededException for a CreateIdentityPool call with {quota + 1} "
            f"CognitoIdentityProviders (one past the discovered quota of {quota}), but it "
            f"SUCCEEDED and created {over_pool_id!r}"
        )
    assert code == "LimitExceededException", (
        f"expected LimitExceededException for a CreateIdentityPool call with {quota + 1} "
        f"CognitoIdentityProviders, got {code}"
    )
    expected = f"Cognito Sign In Providers per Identity pool limit of {quota} reached."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Boundary companion: exactly the discovered quota's worth of providers must be ACCEPTED.
    at_limit_providers = over_limit_providers[:quota]
    resp = ev.create_identity_pool(
        IdentityPoolName=f"sim2real-behav-pool-at-quota-{uuid.uuid4().hex[:8]}".replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=at_limit_providers,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=pool_id))
    assert len(resp.get("CognitoIdentityProviders", [])) == quota, (
        f"expected a CreateIdentityPool call with exactly {quota} providers to be accepted in "
        f"full, got {len(resp.get('CognitoIdentityProviders', []))}"
    )

    # Terminal read: independent of the mutating call's own response, at the destination.
    described = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert len(described.get("CognitoIdentityProviders", [])) == quota, (
        f"DescribeIdentityPool did not independently confirm all {quota} providers persisted, "
        f"got {len(described.get('CognitoIdentityProviders', []))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
