"""deploy-codebuild-report-group-cfn-policy-applies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codebuild-report-group-cfn-policy-applies"
GROUP = "deploy"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ReportGroup provisioned via CloudFormation is a real, addressable ARN:
    PutResourcePolicy against it succeeds and GetResourcePolicy returns the exact
    same policy back."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")

    report_group_name = ctx.unique_name("sim2real-cb-rg-")
    stack_name = ctx.unique_name("sim2real-cb-rgstack-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ReportGroup": {
                    "Type": "AWS::CodeBuild::ReportGroup",
                    "Properties": {
                        "Name": report_group_name,
                        "Type": "TEST",
                        "ExportConfig": {"ExportConfigType": "NO_EXPORT"},
                        "DeleteReports": True,
                    },
                }
            },
        }
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"

    account_id = sts.get_caller_identity()["Account"]
    report_group_arn = (
        f"arn:aws:codebuild:{ctx.region}:{account_id}:report-group/{report_group_name}"
    )

    # Sanity: the ARN we derived is the real, live report group deployed by the stack.
    described = codebuild.batch_get_report_groups(reportGroupArns=[report_group_arn])
    assert report_group_arn in [rg["arn"] for rg in described["reportGroups"]]
    assert not described["reportGroupsNotFound"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfAccountReadOnly",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": [
                    "codebuild:BatchGetReportGroups",
                    "codebuild:BatchGetReports",
                    "codebuild:ListReportsForReportGroup",
                    "codebuild:DescribeTestCases",
                ],
                "Resource": report_group_arn,
            }
        ],
    }
    codebuild.put_resource_policy(resourceArn=report_group_arn, policy=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_policy(codebuild, report_group_arn))

    fetched = codebuild.get_resource_policy(resourceArn=report_group_arn)
    fetched_doc = json.loads(fetched["policy"])
    statement = fetched_doc["Statement"][0]
    assert statement["Effect"] == "Allow"
    resource_val = statement["Resource"]
    resource_vals = resource_val if isinstance(resource_val, list) else [resource_val]
    assert report_group_arn in resource_vals
    action_val = statement["Action"]
    action_vals = action_val if isinstance(action_val, list) else [action_val]
    assert sorted(action_vals) == sorted(policy_doc["Statement"][0]["Action"])
    principal = statement["Principal"]
    principal_aws = principal["AWS"] if isinstance(principal, dict) else principal
    principal_vals = principal_aws if isinstance(principal_aws, list) else [principal_aws]
    expected_principals = {account_id, f"arn:aws:iam::{account_id}:root"}
    assert any(p in expected_principals for p in principal_vals), principal_vals


def _delete_policy(codebuild, resource_arn: str) -> None:
    """Teardown: delete the resource policy, tolerating only its not-found."""
    try:
        codebuild.delete_resource_policy(resourceArn=resource_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
