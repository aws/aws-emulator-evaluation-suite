"""resource-policy-sharing-not-listed-for-owner."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-sharing-not-listed-for-owner"
GROUP = "server-side"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A report-group resource policy round-trips exactly through GetResourcePolicy, yet the
    owner's own ListSharedReportGroups never lists the group: it lists groups shared WITH you.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/report-groups-sharing.html
    """
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-cbrg-")
    group = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]
    group_arn = group["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=group_arn, deleteReports=True))

    # Baseline: no policy attached yet.
    baseline_code, baseline_code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=group_arn))
    assert baseline_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException before any policy is attached, got {baseline_code!r}"
    )
    assert baseline_code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {baseline_code_msg!r}"

    # Granted to the owner's own root: there is no second account to act as a consumer.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadOnlyAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
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
    codebuild.put_resource_policy(resourceArn=group_arn, policy=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(codebuild, group_arn))

    stored = json.loads(codebuild.get_resource_policy(resourceArn=group_arn)["policy"])
    assert stored == policy, f"policy content mismatch: {stored} != {policy}"

    # Yet the owner's own ListSharedReportGroups call must not surface its own group.
    shared_arns = _collect_all(codebuild.list_shared_report_groups, "reportGroups")
    assert group_arn not in shared_arns, (
        f"owner's ListSharedReportGroups leaked its own report group {group_arn!r}: {shared_arns}"
    )


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
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


def _collect_all(list_fn: Any, key: str) -> list[str]:
    items: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = list_fn(**kwargs)
        items.extend(resp.get(key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

