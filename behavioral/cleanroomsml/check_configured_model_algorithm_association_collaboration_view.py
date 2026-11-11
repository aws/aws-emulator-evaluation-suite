"""configured-model-algorithm-association-collaboration-view."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configured-model-algorithm-association-collaboration-view"
GROUP = "collaboration-scoping"
SERVICES = ["cleanroomsml"]

# external-identity: a ConfiguredModelAlgorithm must reference a real, readable
# container image; this is a published AWS-owned SageMaker built-in algorithm image,
# not a resource the check could create itself.
_ALGORITHM_IMAGE_URI = "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.5-1"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_algorithm_with_retry(crml, *, timeout_s: float = 90.0, **kwargs):
    # IAM role propagation: the service assumes the role synchronously on create.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return crml.create_configured_model_algorithm(**kwargs)["configuredModelAlgorithmArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"CreateConfiguredModelAlgorithm never succeeded, likely IAM propagation delay: {last_exc}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ConfiguredModelAlgorithmAssociation created on a membership is visible, with
    identical fields, through both the membership-scoped and the collaboration-scoped
    Get and List operations."""
    iam = ctx.client("iam")
    cr = ctx.client("cleanrooms")
    crml = ctx.client("cleanroomsml")

    role_name = ctx.unique_name("sim2real-crml-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms-ml.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ecr_policy_name = "sim2real-crml-ecr"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=ecr_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchCheckLayerAvailability",
                ],
                "Resource": "*",
            }],
        }),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=ecr_policy_name), "NoSuchEntity"
    ))

    algo_name = ctx.unique_name("sim2real-crml-algo-")
    algo_arn = _create_algorithm_with_retry(
        crml,
        name=algo_name,
        roleArn=role_arn,
        trainingContainerConfig={"imageUri": _ALGORITHM_IMAGE_URI},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: crml.delete_configured_model_algorithm(configuredModelAlgorithmArn=algo_arn),
        "ResourceNotFoundException",
    ))

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-crml-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["collaboration"]
    collab_id = collab["id"]
    ctx.on_cleanup(_teardown(
        lambda: cr.delete_collaboration(collaborationIdentifier=collab_id), "ResourceNotFoundException"
    ))

    membership = cr.create_membership(
        collaborationIdentifier=collab_id,
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["membership"]
    membership_id = membership["id"]
    # The creator's own membership cannot be deleted directly while ACTIVE; deleting
    # the collaboration (cleaned up above) cascades it instead.

    assoc_name = ctx.unique_name("sim2real-crml-assoc-")
    assoc = crml.create_configured_model_algorithm_association(
        membershipIdentifier=membership_id,
        configuredModelAlgorithmArn=algo_arn,
        name=assoc_name,
        tags={"sim2real": CHECK},
    )
    assoc_arn = assoc["configuredModelAlgorithmAssociationArn"]
    ctx.on_cleanup(_teardown(
        lambda: crml.delete_configured_model_algorithm_association(
            membershipIdentifier=membership_id,
            configuredModelAlgorithmAssociationArn=assoc_arn,
        ),
        "ResourceNotFoundException",
    ))

    by_membership = crml.get_configured_model_algorithm_association(
        membershipIdentifier=membership_id,
        configuredModelAlgorithmAssociationArn=assoc_arn,
    )
    by_collaboration = crml.get_collaboration_configured_model_algorithm_association(
        collaborationIdentifier=collab_id,
        configuredModelAlgorithmAssociationArn=assoc_arn,
    )

    assert by_membership["name"] == assoc_name, (
        f"expected membership-scoped name {assoc_name!r}, got {by_membership['name']!r}"
    )
    assert by_collaboration["name"] == assoc_name, (
        f"expected collaboration-scoped name {assoc_name!r}, got {by_collaboration['name']!r}"
    )
    assert by_membership["configuredModelAlgorithmArn"] == algo_arn, (
        f"expected membership-scoped algorithm arn {algo_arn!r}, "
        f"got {by_membership['configuredModelAlgorithmArn']!r}"
    )
    assert by_collaboration["configuredModelAlgorithmArn"] == algo_arn, (
        f"expected collaboration-scoped algorithm arn {algo_arn!r}, "
        f"got {by_collaboration['configuredModelAlgorithmArn']!r}"
    )
    assert by_collaboration["membershipIdentifier"] == membership_id, (
        f"expected collaboration-scoped view to carry membershipIdentifier {membership_id!r}, "
        f"got {by_collaboration['membershipIdentifier']!r}"
    )
    assert by_membership["createTime"] == by_collaboration["createTime"], (
        "expected both scoped views to report the same createTime for one resource: "
        f"{by_membership['createTime']!r} != {by_collaboration['createTime']!r}"
    )

    membership_list = crml.list_configured_model_algorithm_associations(
        membershipIdentifier=membership_id,
    )["configuredModelAlgorithmAssociations"]
    collaboration_list = crml.list_collaboration_configured_model_algorithm_associations(
        collaborationIdentifier=collab_id,
    )["collaborationConfiguredModelAlgorithmAssociations"]

    assert any(a["configuredModelAlgorithmAssociationArn"] == assoc_arn for a in membership_list), (
        f"expected {assoc_arn!r} in membership-scoped list, got {membership_list!r}"
    )
    assert any(a["configuredModelAlgorithmAssociationArn"] == assoc_arn for a in collaboration_list), (
        f"expected {assoc_arn!r} in collaboration-scoped list, got {collaboration_list!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
