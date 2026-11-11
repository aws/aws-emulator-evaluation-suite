"""op-create-children-require-existing-cluster."""
from __future__ import annotations

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

CHECK = "op-create-children-require-existing-cluster"
GROUP = 'overly-permissive'
SERVICES = ['eks']

ACCESS_POLICY_VIEW_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAddon, CreateAccessEntry, AssociateAccessPolicy and AssociateIdentityProviderConfig on a missing
    cluster fail with ResourceNotFoundException and their exact messages instead of creating the parent;
    creates that pass an IAM role are authorized first, so they are not asserted here."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")
    principal = _unused_role_arn(ctx, "eks-principal-")

    no_cluster = f"No cluster found for name: {ghost}."
    # AssociateAccessPolicy reports the missing parent with EKS's generic not-found text.
    creates = {
        "CreateAddon": (lambda: c.create_addon(
            clusterName=ghost, addonName="vpc-cni"
        ), no_cluster),
        "CreateAccessEntry": (lambda: c.create_access_entry(
            clusterName=ghost, principalArn=principal
        ), no_cluster),
        "AssociateAccessPolicy": (lambda: c.associate_access_policy(
            clusterName=ghost,
            principalArn=principal,
            policyArn=ACCESS_POLICY_VIEW_ARN,
            accessScope={"type": "cluster"},
        ), "The requested resource does not exist."),
        "AssociateIdentityProviderConfig": (lambda: c.associate_identity_provider_config(
            clusterName=ghost,
            oidc={
                "identityProviderConfigName": "sim2real-oidc",
                "issuerUrl": "https://example.com",
                "clientId": "sim2real",
            },
        ), no_cluster),
    }
    for op, (fn, expected_msg) in creates.items():
        code, msg = _expect_error(fn)
        assert code == "ResourceNotFoundException", f"{op} -> {code}"
        assert msg == expected_msg, f"{op} -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
