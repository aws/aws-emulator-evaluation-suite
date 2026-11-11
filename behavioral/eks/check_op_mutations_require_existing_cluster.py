"""op-mutations-require-existing-cluster."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

def _unused_role_arn(ctx, label):
    """A well-formed IAM role ARN in this account that does not exist."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-' + label)}"

CHECK = "op-mutations-require-existing-cluster"
GROUP = 'overly-permissive'
SERVICES = ['eks']

ACCESS_POLICY_VIEW_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Update/Delete/introspection operations that target a missing cluster
    (or its children) MUST fail with ResourceNotFoundException rather than succeeding as no-ops
    or, for the list operation, silently returning an empty result."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")
    role = _unused_role_arn(ctx, "eks-mut-role-")

    mutations = {
        "UpdateNodegroupConfig": lambda: c.update_nodegroup_config(
            clusterName=ghost,
            nodegroupName="ng",
            scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 1},
        ),
        "UpdateNodegroupVersion": lambda: c.update_nodegroup_version(
            clusterName=ghost, nodegroupName="ng", version="1.31"
        ),
        "DeleteNodegroup": lambda: c.delete_nodegroup(
            clusterName=ghost, nodegroupName="ng"
        ),
        "UpdateAddon": lambda: c.update_addon(
            clusterName=ghost, addonName="vpc-cni"
        ),
        "DeleteAddon": lambda: c.delete_addon(
            clusterName=ghost, addonName="vpc-cni"
        ),
        "DeleteFargateProfile": lambda: c.delete_fargate_profile(
            clusterName=ghost, fargateProfileName="fp"
        ),
        "UpdateAccessEntry": lambda: c.update_access_entry(
            clusterName=ghost, principalArn=role, kubernetesGroups=["g"]
        ),
        "DeleteAccessEntry": lambda: c.delete_access_entry(
            clusterName=ghost, principalArn=role
        ),
        "DisassociateAccessPolicy": lambda: c.disassociate_access_policy(
            clusterName=ghost, principalArn=role, policyArn=ACCESS_POLICY_VIEW_ARN
        ),
        # NOTE: EKS has no CancelUpdate API (updates are not cancellable);
        # DescribeUpdate below covers the update-read path on a missing cluster.
        "DescribeUpdate": lambda: c.describe_update(
            name=ghost, updateId=str(uuid.uuid4())
        ),
        "DescribeInsight": lambda: c.describe_insight(
            clusterName=ghost, id=str(uuid.uuid4())
        ),
        "ListInsights": lambda: c.list_insights(clusterName=ghost),
        "DeregisterCluster": lambda: c.deregister_cluster(name=ghost),
    }
    # Cluster-scoped reads name the missing cluster; child-resource mutations answer with
    # EKS's generic not-found text.
    names_cluster = {"DescribeUpdate", "DescribeInsight", "ListInsights", "DeregisterCluster"}
    for op, fn in mutations.items():
        code, msg = _expect_error(fn)
        assert code == "ResourceNotFoundException", (
            f"{op}: expected ResourceNotFoundException, got {code!r}"
        )
        expected_msg = (
            f"No cluster found for name: {ghost}."
            if op in names_cluster
            else "The requested resource does not exist."
        )
        assert msg == expected_msg, f"{op}: {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
