"""resource-policy-invalid-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-invalid-document-rejected"
GROUP = "data-plane"
SERVICES = ["codebuild"]


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a policy document naming an action CodeBuild resource
    policies don't support, leaves no policy attached, while a well-formed policy on the
    same resource (in-file positive control) is accepted and readable."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:root"

    name = ctx.unique_name("sim2real-behav-rg-")
    report_group_arn = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=report_group_arn, deleteReports=True))

    bad_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BadAction",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "codebuild:ThisActionDoesNotExist",
                    "Resource": report_group_arn,
                }
            ],
        }
    )

    code, code_msg = _client_error(lambda: codebuild.put_resource_policy(resourceArn=report_group_arn, policy=bad_policy))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    assert code_msg == "Proposed policy was not valid: InvalidPolicy: Input policy containing action that is not allowed for resource type codebuild:ReportGroup", f"unexpected message: {code_msg!r}"

    # Effect absent: no policy was attached by the rejected call.
    no_policy_code, no_policy_code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=report_group_arn))
    assert no_policy_code == "ResourceNotFoundException", (
        f"rejected PutResourcePolicy must not attach a policy, but get returned code {no_policy_code!r}"
    )
    assert no_policy_code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {no_policy_code_msg!r}"

    # Positive control: a well-formed policy on the same resource is accepted.
    good_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "codebuild:BatchGetReportGroups",
                    "Resource": report_group_arn,
                }
            ],
        }
    )
    codebuild.put_resource_policy(resourceArn=report_group_arn, policy=good_policy)
    ctx.on_cleanup(lambda: codebuild.delete_resource_policy(resourceArn=report_group_arn))
    fetched = codebuild.get_resource_policy(resourceArn=report_group_arn)["policy"]
    assert json.loads(fetched) == json.loads(good_policy), (
        f"expected the persisted policy to equal the well-formed policy just put, got {fetched!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
