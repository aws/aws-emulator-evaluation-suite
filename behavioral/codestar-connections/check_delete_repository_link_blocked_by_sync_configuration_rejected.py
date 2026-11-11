"""delete-repository-link-blocked-by-sync-configuration-rejected."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-link-blocked-by-sync-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]+;")


def _mask_request_id(message: str) -> str:
    """AWS appends a per-request backend Request ID to every CodeConnections refusal; mask it."""
    return _REQUEST_ID.sub("Request ID: <id>;", message)


def _suffix(status: int, code: str) -> str:
    """The service-framework tail of a CodeConnections refusal message."""
    return (
        f" (Service: CodeConnections; Status Code: {status}; Error Code: {code}; "
        "Request ID: <id>; Proxy: null)"
    )


def _create_sync_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-syncrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.sync.codeconnections.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    permissions = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SyncToCloudFormation",
                "Effect": "Allow",
                "Action": [
                    "cloudformation:CreateChangeSet",
                    "cloudformation:DeleteChangeSet",
                    "cloudformation:DescribeChangeSet",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:DescribeStacks",
                    "cloudformation:ExecuteChangeSet",
                    "cloudformation:GetTemplate",
                    "cloudformation:ListChangeSets",
                    "cloudformation:ListStacks",
                    "cloudformation:ValidateTemplate",
                ],
                "Resource": "*",
            },
            {
                "Sid": "PolicyForManagedRules",
                "Effect": "Allow",
                "Action": ["events:PutRule", "events:PutTargets"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "events:ManagedBy": ["cloudformation.sync.codeconnections.amazonaws.com"]
                    }
                },
            },
            {
                "Sid": "PolicyForDescribingRule",
                "Effect": "Allow",
                "Action": "events:DescribeRule",
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sync-permissions", PolicyDocument=json.dumps(permissions)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sync-permissions"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _create_sync_configuration_retrying(csc, *, timeout_s: float = 45.0, **kwargs):
    """CreateSyncConfiguration can transiently AccessDeny while the just-created
    IAM role is still propagating; poll until the call itself succeeds or a
    non-propagation error surfaces."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return csc.create_sync_configuration(**kwargs)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"CreateSyncConfiguration never succeeded past IAM propagation: {last_code}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryLink on a link a sync configuration uses fails with SyncConfigurationStillExistsException
    and its exact message and the link survives; after the sync configuration is deleted the link deletes and
    then reads as ResourceNotFoundException.
    """
    csc = ctx.client("codestar-connections")
    role_arn = _create_sync_role(ctx)

    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"),
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    link_id = csc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId="sim2real-owner",
        RepositoryName=repo_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]

    resource_name = ctx.unique_name("sim2real-behav-stack-")
    _create_sync_configuration_retrying(
        csc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )
    def _cleanup_sync_config():
        try:
            csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_sync_config)

    def _cleanup_link():
        try:
            csc.delete_repository_link(RepositoryLinkId=link_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_link)

    code, message = _error_code(lambda: csc.delete_repository_link(RepositoryLinkId=link_id))
    assert code == "SyncConfigurationStillExistsException", (
        f"expected SyncConfigurationStillExistsException, got {code}"
    )
    expected_message = f"Cfn stack sync configurations still exist for repository sim2real-owner/{repo_name}. Please delete them before retrying." + _suffix(409, "ResourceStillExistsException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # Effect absent: the link is still there.
    still_there = csc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert still_there["RepositoryLinkId"] == link_id, (
        f"expected the link {link_id} to survive the rejected delete, got {still_there!r}"
    )

    # Positive control: removing the sync configuration unblocks the delete.
    csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    csc.delete_repository_link(RepositoryLinkId=link_id)
    code_after, code_after_message = _error_code(lambda: csc.get_repository_link(RepositoryLinkId=link_id))
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after the unblocked delete, got {code_after}"
    )
    expected_code_after_message = f"Repository not found for accountId: {ctx.account} and uuid: {link_id}" + _suffix(404, "ResourceNotFoundException")
    assert code_after_message == expected_code_after_message, (
        f"the refusal said {code_after_message!r}, expected {expected_code_after_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
