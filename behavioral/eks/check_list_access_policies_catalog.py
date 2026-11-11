"""list-access-policies-catalog."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-access-policies-catalog"
GROUP = 'metadata'
SERVICES = ['eks']

ACCESS_POLICY_VIEW_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

ACCESS_POLICY_ADMIN_ARN = (
    "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
)


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAccessPolicies returns the AWS-managed cluster access policy catalog including AmazonEKSClusterAdminPolicy."""
    c = ctx.client("eks")
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = c.list_access_policies(**kwargs)
        for policy in resp.get("accessPolicies", []):
            assert policy["name"], policy
            assert policy["arn"].startswith(
                "arn:aws:eks::aws:cluster-access-policy/"
            ), policy["arn"]
            arns.append(policy["arn"])
        token = resp.get("nextToken")
        if not token:
            break

    assert ACCESS_POLICY_ADMIN_ARN in arns, arns
    assert ACCESS_POLICY_VIEW_ARN in arns, arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
