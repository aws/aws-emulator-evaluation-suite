"""access-policy-catalog-scope-metadata."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "access-policy-catalog-scope-metadata"
GROUP = 'metadata'
SERVICES = ['eks']

ACCESS_POLICY_VIEW_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
ACCESS_POLICY_ADMIN_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

# The AccessPolicy shape carries only {name, arn} — the API exposes no
# per-policy scope metadata (confirmed against the Smithy model: there is no
# supportedAccessScopeTypes member). A floor on catalog size is what keeps a
# hand-picked 2-entry stub from passing this check.
_MIN_CATALOG_SIZE = 20


def _fetch_catalog(c):
    policies = {}
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = c.list_access_policies(**kwargs)
        for policy in resp.get("accessPolicies", []):
            arn = policy["arn"]
            assert arn not in policies, f"{arn} repeated across pages"
            policies[arn] = policy
        token = resp.get("nextToken")
        if not token:
            break
    return policies


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAccessPolicies returns AWS's real managed policy catalog: a large, stable set of exact
    {name, arn} pairs, unchanged across repeated reads and pagination, including the well-known
    admin/view policies."""
    c = ctx.client("eks")
    policies = _fetch_catalog(c)

    assert len(policies) >= _MIN_CATALOG_SIZE, (
        f"expected the real managed catalog (>= {_MIN_CATALOG_SIZE} policies), "
        f"got {len(policies)}: {sorted(policies)}"
    )
    assert ACCESS_POLICY_ADMIN_ARN in policies, sorted(policies)
    assert ACCESS_POLICY_VIEW_ARN in policies, sorted(policies)

    for arn, policy in policies.items():
        assert policy["name"], policy
        assert arn == f"arn:aws:eks::aws:cluster-access-policy/{policy['name']}", policy

    admin = policies[ACCESS_POLICY_ADMIN_ARN]
    assert admin["name"] == "AmazonEKSClusterAdminPolicy", admin

    # The catalog is an AWS-managed, account-independent singleton: state must
    # not advance on a read, so a second independent fetch must agree exactly.
    assert _fetch_catalog(c) == policies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
