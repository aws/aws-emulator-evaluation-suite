"""op-associate-access-policy-scope-validation."""
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

CHECK = "op-associate-access-policy-scope-validation"
GROUP = 'overly-permissive'
SERVICES = ['eks']

ACCESS_POLICY_VIEW_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] AssociateAccessPolicy resolves the cluster before it validates the access scope or the policy ARN: against a missing cluster, a structurally empty namespace scope and an unknown policy ARN both answer ResourceNotFoundException, so an emulator must not reject either body with InvalidParameterException first."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")
    principal = _unused_role_arn(ctx, "eks-scope-role-")

    # A namespace-typed grant that names no namespaces is structurally
    # incoherent, yet the missing cluster is reported first.
    code, msg = _expect_error(
        lambda: c.associate_access_policy(
            clusterName=ghost,
            principalArn=principal,
            policyArn=ACCESS_POLICY_VIEW_ARN,
            accessScope={"type": "namespace"},
        )
    )
    assert code == "ResourceNotFoundException", f"empty namespace scope -> {code}: {msg}"
    assert msg == "The requested resource does not exist.", f"empty namespace scope -> {msg!r}"

    # An unknown policy ARN is likewise only consulted after the cluster is
    # resolved, so the missing cluster wins for an otherwise well-formed body.
    code, msg = _expect_error(
        lambda: c.associate_access_policy(
            clusterName=ghost,
            principalArn=principal,
            policyArn="arn:aws:eks::aws:cluster-access-policy/NotARealPolicy",
            accessScope={"type": "cluster"},
        )
    )
    assert code == "ResourceNotFoundException", f"unknown policy arn -> {code}: {msg}"
    assert msg == "The requested resource does not exist.", f"unknown policy arn -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
