"""delete-workflow-referenced-by-server-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-workflow-referenced-by-server-rejected"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflow fails with InvalidRequestException and the exact message while a server's WorkflowDetails
    references the workflow, which stays describable; once the reference is cleared the delete succeeds and
    DescribeWorkflow fails with ResourceNotFoundException "Unknown workflow"."""
    transfer = ctx.client("transfer")
    execution_role_arn = _create_transfer_role(ctx)

    workflow_id = transfer.create_workflow(
        Steps=[
            {
                "Type": "TAG",
                "TagStepDetails": {
                    "Name": "noop-tag",
                    "Tags": [{"Key": "sim2real", "Value": "true"}],
                },
            }
        ]
    )["WorkflowId"]
    ctx.on_cleanup(lambda: _safe_delete_workflow(transfer, workflow_id))

    server_id = _create_server_with_role_retry(ctx, transfer, workflow_id, execution_role_arn)
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    code, message = _error(lambda: transfer.delete_workflow(WorkflowId=workflow_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = f"Workflow is still in use by server {server_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the workflow still exists, unaffected by the rejected delete
    workflow_after_reject = transfer.describe_workflow(WorkflowId=workflow_id)["Workflow"]["WorkflowId"]
    assert workflow_after_reject == workflow_id, (
        f"expected workflow {workflow_id} to survive the rejected delete, got {workflow_after_reject}"
    )

    # Positive control: once the server no longer references the workflow, deleting it succeeds
    transfer.update_server(ServerId=server_id, WorkflowDetails={"OnUpload": []})
    transfer.delete_workflow(WorkflowId=workflow_id)
    deleted_code, deleted_message = _error(lambda: transfer.describe_workflow(WorkflowId=workflow_id))
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code}"
    )
    assert deleted_message == "Unknown workflow", (
        f"expected message 'Unknown workflow', got {deleted_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_workflow(transfer, workflow_id: str) -> None:
    try:
        transfer.delete_workflow(WorkflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-wfref-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="minimal",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="minimal")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_server_with_role_retry(ctx, transfer, workflow_id: str, execution_role_arn: str) -> str:
    """IAM role trust is eventually consistent: CreateServer can transiently reject a
    just-created ExecutionRole before it is visible, so retry within a bounded window
    instead of a fixed sleep."""
    deadline = time.monotonic() + 60.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            return transfer.create_server(
                Protocols=["SFTP"],
                IdentityProviderType="SERVICE_MANAGED",
                Domain="S3",
                EndpointType="PUBLIC",
                WorkflowDetails={
                    "OnUpload": [{"WorkflowId": workflow_id, "ExecutionRole": execution_role_arn}]
                },
                Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-wfref-srv-")}],
            )["ServerId"]
        except ClientError as e:
            last_error = e
            time.sleep(5)
    raise AssertionError(f"CreateServer did not accept the new role within 60s: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
