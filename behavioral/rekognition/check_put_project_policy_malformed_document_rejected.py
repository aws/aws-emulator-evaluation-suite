"""put-project-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-project-policy-malformed-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutProjectPolicy rejects invalid JSON and a policy naming a nonexistent project-version ARN, each
    with MalformedPolicyDocumentException and its exact message, and attaches nothing."""
    rek = ctx.client("rekognition")
    sts = ctx.client("sts")
    project_name = ctx.unique_name("sim2real-rek-polproj-")
    project_arn = rek.create_project(ProjectName=project_name, Tags={"sim2real": CHECK})[
        "ProjectArn"
    ]
    ctx.on_cleanup(lambda: rek.delete_project(ProjectArn=project_arn))

    account_id = sts.get_caller_identity()["Account"]
    policy_name = "sim2realtestpolicy"

    def _policy_for(resource_arn):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCopy",
                        "Effect": "Allow",
                        "Principal": {"AWS": account_id},
                        "Action": "rekognition:CopyProjectVersion",
                        "Resource": resource_arn,
                    }
                ],
            }
        )

    # boundary 1: syntactically invalid JSON
    code_bad_json, message_bad_json = _client_error(
        lambda: rek.put_project_policy(
            ProjectArn=project_arn,
            PolicyName=policy_name,
            PolicyDocument="{this is not valid json",
        )
    )
    assert code_bad_json == "MalformedPolicyDocumentException", (
        f"expected MalformedPolicyDocumentException for invalid JSON, got {code_bad_json!r}"
    )
    assert message_bad_json == "Request contains a malformed policy.", (
        f"expected the malformed-policy message for invalid JSON, got {message_bad_json!r}"
    )

    # boundary 2: syntactically valid IAM JSON, but the Resource is a bare project ARN rather
    # than the project-VERSION-shaped ARN (project/<name>/version/<version>/<ts>) Rekognition
    # requires for a CopyProjectVersion resource policy — rejected as an invalid resource even
    # though the JSON itself parses fine.
    code_bad_resource, message_bad_resource = _client_error(
        lambda: rek.put_project_policy(
            ProjectArn=project_arn, PolicyName=policy_name, PolicyDocument=_policy_for(project_arn)
        )
    )
    assert code_bad_resource == "MalformedPolicyDocumentException", (
        f"expected MalformedPolicyDocumentException for a bare project ARN, got {code_bad_resource!r}"
    )
    assert message_bad_resource == "Request contains an invalid resource in the provided policy.", (
        f"expected the invalid-resource message for a bare project ARN, got {message_bad_resource!r}"
    )

    # effect absent: neither rejected attempt attached anything
    listed = rek.list_project_policies(ProjectArn=project_arn)
    assert listed["ProjectPolicies"] == [], (
        f"expected no attached policies after both rejected attempts, saw "
        f"{listed['ProjectPolicies']!r}"
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

