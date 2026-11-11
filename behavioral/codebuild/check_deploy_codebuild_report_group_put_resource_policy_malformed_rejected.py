"""deploy-codebuild-report-group-put-resource-policy-malformed-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codebuild-report-group-put-resource-policy-malformed-rejected"
GROUP = "deploy"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a CloudFormation-deployed ReportGroup rejects a malformed policy with
    InvalidInputException and attaches nothing; a well-formed policy on it still succeeds."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")

    report_group_name = ctx.unique_name("sim2real-cb-rgneg-")
    stack_name = ctx.unique_name("sim2real-cb-rgnegstack-")

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

    # Break exactly one thing: the policy body is not valid JSON.
    malformed_policy = "{not valid json ["
    code, message = _client_error(lambda: codebuild.put_resource_policy(
        resourceArn=report_group_arn, policy=malformed_policy
    ))
    assert code == "InvalidInputException", code
    assert message == "Problem parsing given policy", message

    # Effect absent: no policy was ever attached to the report group.
    code2, message2 = _client_error(
        lambda: codebuild.get_resource_policy(resourceArn=report_group_arn)
    )
    assert code2 == "ResourceNotFoundException", code2
    assert message2 == "Resource ARN resource policy does not exist", message2

    # Positive control: a well-formed policy on the same resource succeeds and is retrievable.
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfAccountReadOnly",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": ["codebuild:BatchGetReportGroups"],
                "Resource": report_group_arn,
            }
        ],
    }
    codebuild.put_resource_policy(resourceArn=report_group_arn, policy=json.dumps(good_policy))
    ctx.on_cleanup(lambda: _delete_policy(codebuild, report_group_arn))
    fetched = codebuild.get_resource_policy(resourceArn=report_group_arn)
    fetched_doc = json.loads(fetched["policy"])
    action_val = fetched_doc["Statement"][0]["Action"]
    action_vals = action_val if isinstance(action_val, list) else [action_val]
    assert action_vals == ["codebuild:BatchGetReportGroups"], action_vals


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
