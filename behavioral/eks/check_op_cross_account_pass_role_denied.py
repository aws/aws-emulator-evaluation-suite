"""op-cross-account-pass-role-denied."""
from __future__ import annotations

import json

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

def _foreign_role_arn(ctx, label):
    """A well-formed role ARN definitively in a different account (cross-account PassRole probe)."""
    return f"arn:aws:iam::111122223333:role/{ctx.unique_name('sim2real-behav-' + label)}"

def _local_role_arn(ctx, principal, label):
    """A real role this account owns, trusted by the given service principal."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-" + label)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-behav", "Value": "eks-cross-account-pass-role"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]

CHECK = "op-cross-account-pass-role-denied"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Every EKS create that accepts an IAM role MUST authorize iam:PassRole BEFORE it validates the body or resolves the cluster: a cross-account role yields AccessDeniedException even when the name is illegal and the cluster is absent. Positive control: the identical malformed body with a role this account owns fails for the OTHER reason instead, proving the denial below is earned by the foreign account and not by the fact that every one of these calls is doomed anyway."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")
    foreign = _foreign_role_arn(ctx, "eks-foreign-role-")
    subnets = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0bbbbbbbbbbbbbbb2"]

    # Positive control: the identical malformed body, but with a role this
    # account actually owns for each op's expected trust principal. If the
    # foreign-role case below is denied only because the ARN is foreign (not
    # because these bodies are doomed regardless of the role), the same body
    # with a local role must fail for a DIFFERENT reason than PassRole.
    local_cluster_role = _local_role_arn(ctx, "eks.amazonaws.com", "eks-local-cluster-role-")
    local_node_role = _local_role_arn(ctx, "ec2.amazonaws.com", "eks-local-node-role-")
    local_fargate_role = _local_role_arn(ctx, "eks-fargate-pods.amazonaws.com", "eks-local-fargate-role-")
    positive_calls = {
        "CreateCluster": lambda: c.create_cluster(
            name="sim2real behav bad name!",
            roleArn=local_cluster_role,
            resourcesVpcConfig={"subnetIds": subnets},
        ),
        "CreateNodegroup": lambda: c.create_nodegroup(
            clusterName=ghost,
            nodegroupName="ng",
            subnets=subnets,
            nodeRole=local_node_role,
            scalingConfig={"minSize": 5, "maxSize": 1, "desiredSize": 3},
        ),
        "CreateFargateProfile": lambda: c.create_fargate_profile(
            clusterName=ghost,
            fargateProfileName="fp",
            podExecutionRoleArn=local_fargate_role,
            subnets=subnets,
            selectors=[{"namespace": "default"}],
        ),
    }
    for op, fn in positive_calls.items():
        code, msg = _expect_error(fn)
        assert code != "AccessDeniedException", (
            f"{op} with an in-account role still returned AccessDeniedException ({msg}) -- "
            "the malformed body alone denies the call, so the foreign-role case below proves nothing"
        )
        assert "pass role" not in msg.lower(), f"{op} with an in-account role -> unexpected message: {msg}"

    # Each request below is invalid in at least two further ways (illegal
    # cluster name / missing cluster / nonexistent subnets), so a service that
    # checked the body or the parent first would answer with
    # InvalidParameterException or ResourceNotFoundException instead.
    pass_role_calls = {
        "CreateCluster": lambda: c.create_cluster(
            name="sim2real behav bad name!",
            roleArn=foreign,
            resourcesVpcConfig={"subnetIds": subnets},
        ),
        "CreateNodegroup": lambda: c.create_nodegroup(
            clusterName=ghost,
            nodegroupName="ng",
            subnets=subnets,
            nodeRole=foreign,
            scalingConfig={"minSize": 5, "maxSize": 1, "desiredSize": 3},
        ),
        "CreateFargateProfile": lambda: c.create_fargate_profile(
            clusterName=ghost,
            fargateProfileName="fp",
            podExecutionRoleArn=foreign,
            subnets=subnets,
            selectors=[{"namespace": "default"}],
        ),
    }
    for op, fn in pass_role_calls.items():
        code, msg = _expect_error(fn)
        assert code == "AccessDeniedException", f"{op} -> {code}: {msg}"
        assert msg == "Cross-account pass role is not allowed.", f"{op} -> unexpected message: {msg!r}"

    # CreateCluster authorizes the PassRole so early that even a *syntactically* malformed role ARN
    # is reported as a denied pass-role rather than a parameter problem. The positive control above
    # already shows a local role clears CreateCluster's PassRole gate for this exact (bad-name)
    # body, so this reuses that same op with the ARN itself broken. Note the asymmetry with
    # RegisterCluster, which validates its connector role ARN's syntax first and answers
    # InvalidParameterException for the same input.
    code, msg = _expect_error(
        lambda: c.create_cluster(
            name=ctx.unique_name("sim2real-behav-eks-badrole-"),
            roleArn="not-an-arn",
            resourcesVpcConfig={"subnetIds": subnets},
        )
    )
    assert code == "AccessDeniedException", f"malformed role arn -> {code}: {msg}"
    assert msg == "Cross-account pass role is not allowed.", f"malformed role arn -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
