"""delete-project-policy-wrong-revision-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-project-policy-wrong-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProjectPolicy answers ResourceNotFoundException before any policy is attached and
    InvalidPolicyRevisionIdException for a wrong revision once one is, each with its exact message
    and leaving policies unchanged; the correct revision then deletes it."""
    rek = ctx.client("rekognition")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    project_name = ctx.unique_name("sim2real-rek-polrev-")
    project_arn = rek.create_project(ProjectName=project_name)["ProjectArn"]
    ctx.on_cleanup(lambda: rek.delete_project(ProjectArn=project_arn))

    policy_name = "sim2realtestpolicy"

    # nothing has ever been attached to this brand-new project
    listed = rek.list_project_policies(ProjectArn=project_arn)
    assert listed["ProjectPolicies"] == [], f"expected no policies, got {listed['ProjectPolicies']!r}"

    # boundary 1: delete a policy name that was never attached, no revision id supplied
    policy_not_found_message = (
        f"The specified policy {policy_name} does not exist for project {project_name}."
    )
    code_no_revision, message_no_revision = _client_error(
        lambda: rek.delete_project_policy(ProjectArn=project_arn, PolicyName=policy_name)
    )
    assert code_no_revision == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code_no_revision!r}"
    )
    assert message_no_revision == policy_not_found_message, (
        f"expected {policy_not_found_message!r}, got {message_no_revision!r}"
    )

    # boundary 2: same, but with a syntactically well-formed (all-hex) revision id supplied —
    # still rejected as not-found rather than as a revision mismatch: existence is checked
    # before the revision id is even looked at
    code_with_revision, message_with_revision = _client_error(
        lambda: rek.delete_project_policy(
            ProjectArn=project_arn, PolicyName=policy_name, PolicyRevisionId="deadbeef"
        )
    )
    assert code_with_revision == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code_with_revision!r}"
    )
    assert message_with_revision == policy_not_found_message, (
        f"expected {policy_not_found_message!r}, got {message_with_revision!r}"
    )

    # effect absent: still nothing attached
    listed_after = rek.list_project_policies(ProjectArn=project_arn)
    assert listed_after["ProjectPolicies"] == [], (
        f"expected no policies, got {listed_after['ProjectPolicies']!r}"
    )

    # positive control: attach a real policy so the revision-mismatch error can actually be
    # reached. PutProjectPolicy validates that a policy's Resource is project-version-ARN
    # SHAPED — it does not require the version to have ever been
    # trained — so this attaches a genuine policy without needing a trained model.
    project_base_arn = project_arn.rsplit("/", 1)[0]
    version_arn = f"{project_base_arn}/version/{project_name}.v1/1700000000000"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCopy",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "rekognition:CopyProjectVersion",
                    "Resource": version_arn,
                }
            ],
        }
    )
    revision_id = rek.put_project_policy(
        ProjectArn=project_arn, PolicyName=policy_name, PolicyDocument=policy_doc
    )["PolicyRevisionId"]

    listed_attached = rek.list_project_policies(ProjectArn=project_arn)
    attached_names = [p["PolicyName"] for p in listed_attached["ProjectPolicies"]]
    assert attached_names == [policy_name], f"expected [{policy_name!r}], got {attached_names!r}"

    # boundary 3: a well-formed but WRONG revision id on a policy that really is attached is
    # rejected with the specific revision-mismatch error, not ResourceNotFoundException
    wrong_revision = "".join("0" if c != "0" else "1" for c in revision_id)
    code_wrong_revision, message_wrong_revision = _client_error(
        lambda: rek.delete_project_policy(
            ProjectArn=project_arn, PolicyName=policy_name, PolicyRevisionId=wrong_revision
        )
    )
    assert code_wrong_revision == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException, got {code_wrong_revision!r}"
    )
    wrong_revision_message = (
        "The policy cannot be deleted. Please enter the latest policy revision ID associated "
        f"with the policy {policy_name} and try again."
    )
    assert message_wrong_revision == wrong_revision_message, (
        f"expected {wrong_revision_message!r}, got {message_wrong_revision!r}"
    )

    # effect absent: the real policy survived the wrong-revision delete attempt
    listed_still_attached = rek.list_project_policies(ProjectArn=project_arn)
    still_attached_names = [p["PolicyName"] for p in listed_still_attached["ProjectPolicies"]]
    assert still_attached_names == [policy_name], (
        f"expected [{policy_name!r}], got {still_attached_names!r}"
    )

    # restore: the identical delete call with the CORRECT revision id now succeeds
    rek.delete_project_policy(
        ProjectArn=project_arn, PolicyName=policy_name, PolicyRevisionId=revision_id
    )
    listed_final = rek.list_project_policies(ProjectArn=project_arn)
    assert listed_final["ProjectPolicies"] == [], (
        f"expected no policies after delete, got {listed_final['ProjectPolicies']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
