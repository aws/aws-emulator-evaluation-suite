"""put-resource-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-document-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a syntactically invalid policy document is rejected with
    InvalidInputException, no policy is persisted for the resource, and a well-formed
    policy document for the same resource succeeds afterwards."""
    cb = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-cb-rg-")
    report_group = cb.create_report_group(
        name=group_name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
    )["reportGroup"]
    rg_arn = report_group["arn"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg_arn))

    code, code_msg = _client_error(lambda: cb.put_resource_policy(policy="{not-valid-json", resourceArn=rg_arn))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    assert code_msg == "Problem parsing given policy", f"unexpected message: {code_msg!r}"

    # Effect absent: no policy was persisted by the malformed call.
    absent_code, absent_code_msg = _client_error(lambda: cb.get_resource_policy(resourceArn=rg_arn))
    assert absent_code == "ResourceNotFoundException", (
        f"rejected PutResourcePolicy must not attach a policy, but get returned {absent_code!r}"
    )
    assert absent_code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {absent_code_msg!r}"

    # Positive control: a well-formed resource policy for the same resource succeeds.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSameAccountReportGroupAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "codebuild:BatchGetReportGroups",
                    "codebuild:BatchGetReports",
                    "codebuild:ListReportsForReportGroup",
                    "codebuild:DescribeTestCases",
                ],
                "Resource": rg_arn,
            }
        ],
    }
    cb.put_resource_policy(policy=json.dumps(valid_policy), resourceArn=rg_arn)
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(cb, rg_arn))

    stored = json.loads(cb.get_resource_policy(resourceArn=rg_arn)["policy"])
    assert stored["Statement"][0]["Resource"] == rg_arn, (
        f"expected resource {rg_arn!r}, got {stored['Statement'][0].get('Resource')!r}"
    )
    stored_actions = set(stored["Statement"][0]["Action"])
    expected_actions = set(valid_policy["Statement"][0]["Action"])
    assert stored_actions == expected_actions, (
        f"expected actions {expected_actions}, got {stored_actions}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_resource_policy(cb, resource_arn: str) -> None:
    try:
        cb.delete_resource_policy(resourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInputException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
