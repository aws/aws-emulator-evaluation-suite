"""create-association-nonexistent-algorithm-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-nonexistent-algorithm-rejected"
GROUP = "negative-classes"
SERVICES = ["cleanroomsml"]

# external-identity: a ConfiguredModelAlgorithm must reference a real, readable
# container image; this is a published AWS-owned SageMaker built-in algorithm image,
# not a resource the check could create itself.
_ALGORITHM_IMAGE_URI = "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.5-1"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguredModelAlgorithmAssociation against a nonexistent algorithm ARN
    is rejected with ResourceNotFoundException and leaves no association behind,
    while a positive control on the same membership still succeeds."""
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

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id,
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["membership"]["id"]
    # The creator's own membership cannot be deleted directly while ACTIVE; deleting
    # the collaboration (cleaned up above) cascades it instead.

    missing_arn = algo_arn.rsplit("/", 1)[0] + "/00000000000000000000000000000000"
    code, message = _error(lambda: crml.create_configured_model_algorithm_association(
        membershipIdentifier=membership_id,
        configuredModelAlgorithmArn=missing_arn,
        name=ctx.unique_name("sim2real-crml-assoc-"),
    ))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Configured Model Algorithm: {missing_arn} not found.", f"unexpected message {message!r}"

    listing = crml.list_configured_model_algorithm_associations(membershipIdentifier=membership_id)[
        "configuredModelAlgorithmAssociations"
    ]
    assert listing == [], f"expected no association to have been created by the rejected call, got {listing!r}"

    # Positive control: the same membership, a real algorithm, succeeds.
    assoc_name = ctx.unique_name("sim2real-crml-assoc-")
    assoc_arn = crml.create_configured_model_algorithm_association(
        membershipIdentifier=membership_id,
        configuredModelAlgorithmArn=algo_arn,
        name=assoc_name,
    )["configuredModelAlgorithmAssociationArn"]
    ctx.on_cleanup(_teardown(
        lambda: crml.delete_configured_model_algorithm_association(
            membershipIdentifier=membership_id,
            configuredModelAlgorithmAssociationArn=assoc_arn,
        ),
        "ResourceNotFoundException",
    ))
    fetched = crml.get_configured_model_algorithm_association(
        membershipIdentifier=membership_id, configuredModelAlgorithmAssociationArn=assoc_arn
    )
    assert fetched["name"] == assoc_name, f"expected the positive control's name {assoc_name!r}, got {fetched['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
