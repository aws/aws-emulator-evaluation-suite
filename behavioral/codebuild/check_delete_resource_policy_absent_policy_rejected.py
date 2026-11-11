"""delete-resource-policy-absent-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-resource-policy-absent-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]

# GetResourcePolicy's refusal on a real resource with no policy attached.
_NO_POLICY_MESSAGE = "Resource ARN resource policy does not exist"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a non-existent resource ARN fails with ResourceNotFoundException "Resource
    ARN does not exist", while the policy attached to a real report group deletes and GetResourcePolicy
    then reports it absent."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-behav-cbrg-")
    report_group = codebuild.create_report_group(
        name=group_name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
    )["reportGroup"]
    group_arn = report_group["arn"]
    ctx.on_cleanup(
        lambda: codebuild.delete_report_group(arn=group_arn, deleteReports=True)
    )

    # No policy has ever been attached: GetResourcePolicy confirms the baseline.
    baseline_code, baseline_msg = _client_error(
        lambda: codebuild.get_resource_policy(resourceArn=group_arn)
    )
    assert baseline_code == "ResourceNotFoundException", (
        f"expected no baseline policy (ResourceNotFoundException), got {baseline_code!r}"
    )
    assert baseline_msg == _NO_POLICY_MESSAGE, baseline_msg

    # Break exactly one thing: delete a resource policy for a non-existent
    # (but well-formed) report-group ARN.
    bogus_arn = group_arn + "-does-not-exist-suffix"
    delete_code, delete_msg = _client_error(
        lambda: codebuild.delete_resource_policy(resourceArn=bogus_arn)
    )
    assert delete_code == "ResourceNotFoundException", f"got {delete_code!r} instead"
    assert delete_msg == "Resource ARN does not exist", delete_msg

    # Effect is absent: the real report group still has no policy attached.
    after_reject_code, after_reject_msg = _client_error(
        lambda: codebuild.get_resource_policy(resourceArn=group_arn)
    )
    assert after_reject_code == "ResourceNotFoundException", (
        f"rejected delete must have no effect, got {after_reject_code!r}"
    )
    assert after_reject_msg == _NO_POLICY_MESSAGE, after_reject_msg

    # Positive control: attach a real policy to the real resource, then delete it.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": [
                    "codebuild:BatchGetReportGroups",
                    "codebuild:BatchGetReports",
                    "codebuild:ListReportsForReportGroup",
                    "codebuild:DescribeTestCases",
                ],
                "Resource": group_arn,
            }
        ],
    }
    codebuild.put_resource_policy(policy=json.dumps(policy_doc), resourceArn=group_arn)
    attached = codebuild.get_resource_policy(resourceArn=group_arn)["policy"]
    attached_resource = json.loads(attached)["Statement"][0]["Resource"]
    assert attached_resource == group_arn, (
        f"expected attached policy Resource {group_arn!r}, got {attached_resource!r}"
    )

    codebuild.delete_resource_policy(resourceArn=group_arn)

    after_delete_code, after_delete_msg = _client_error(
        lambda: codebuild.get_resource_policy(resourceArn=group_arn)
    )
    assert after_delete_code == "ResourceNotFoundException", (
        f"expected policy gone after delete (ResourceNotFoundException), got {after_delete_code!r}"
    )
    assert after_delete_msg == _NO_POLICY_MESSAGE, after_delete_msg

    # Documented real-AWS behavior: deleting again (no policy now attached to a
    # *valid* resource) is an idempotent no-op rather than an error.
    codebuild.delete_resource_policy(resourceArn=group_arn)


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
