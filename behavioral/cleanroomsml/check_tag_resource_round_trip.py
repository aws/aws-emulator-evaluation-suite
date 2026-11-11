"""tag-resource-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "tagging"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource on a configured model algorithm ARN persist and
    remove tags as observed through ListTagsForResource, and TagResource against a
    nonexistent algorithm ARN fails with ResourceNotFoundException."""
    iam = ctx.client("iam")
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

    initial = crml.list_tags_for_resource(resourceArn=algo_arn)["tags"]
    assert initial == {"sim2real": CHECK}, f"expected initial tags {{'sim2real': {CHECK!r}}}, got {initial!r}"

    crml.tag_resource(resourceArn=algo_arn, tags={"extra": "value"})
    after_tag = crml.list_tags_for_resource(resourceArn=algo_arn)["tags"]
    assert after_tag == {"sim2real": CHECK, "extra": "value"}, (
        f"expected both tags present after TagResource, got {after_tag!r}"
    )

    crml.untag_resource(resourceArn=algo_arn, tagKeys=["extra"])
    after_untag = crml.list_tags_for_resource(resourceArn=algo_arn)["tags"]
    assert after_untag == {"sim2real": CHECK}, (
        f"expected only the original tag after UntagResource, got {after_untag!r}"
    )

    missing_arn = algo_arn.rsplit("/", 1)[0] + "/00000000000000000000000000000000"
    code, message = _error(lambda: crml.tag_resource(resourceArn=missing_arn, tags={"x": "y"}))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
