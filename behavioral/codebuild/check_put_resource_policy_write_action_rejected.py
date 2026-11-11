"""put-resource-policy-write-action-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-write-action-rejected"
GROUP = "server-side"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a report group rejects a grant of codebuild:DeleteReportGroup with
    InvalidInputException and attaches nothing (only read actions may be shared), while a
    read-only BatchGetReportGroups grant on the same group succeeds and persists.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/report-groups-sharing-perms.html
    """
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-cbrgneg-")
    group = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]
    group_arn = group["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=group_arn, deleteReports=True))

    bad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DisallowedWriteAction",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codebuild:DeleteReportGroup",
                "Resource": group_arn,
            }
        ],
    }
    code, code_msg = _client_error(
        lambda: codebuild.put_resource_policy(resourceArn=group_arn, policy=json.dumps(bad_policy))
    )
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for a policy granting the write action "
        f"codebuild:DeleteReportGroup, got {code!r}"
    )
    assert code_msg == "Proposed policy was not valid: InvalidPolicy: Input policy containing action that is not allowed for resource type codebuild:ReportGroup", f"unexpected message: {code_msg!r}"

    # Effect absent: no policy was stored as a result of the rejected call.
    get_code, get_code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=group_arn))
    assert get_code == "ResourceNotFoundException", (
        f"rejected put_resource_policy must leave no policy attached, "
        f"but get_resource_policy returned {get_code!r} instead of ResourceNotFoundException"
    )
    assert get_code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {get_code_msg!r}"

    # Positive control: the same report group accepts a policy with only a supported read action.
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBatchGetReportGroups",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codebuild:BatchGetReportGroups",
                "Resource": group_arn,
            }
        ],
    }
    codebuild.put_resource_policy(resourceArn=group_arn, policy=json.dumps(good_policy))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(codebuild, group_arn))
    stored = json.loads(codebuild.get_resource_policy(resourceArn=group_arn)["policy"])
    assert stored == good_policy, f"positive-control policy did not persist: {stored}"




def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_resource_policy(codebuild: Any, resource_arn: str) -> None:
    """Teardown: returns when the policy is already gone; any other failure raises."""
    try:
        codebuild.delete_resource_policy(resourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

