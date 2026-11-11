"""get-resource-sync-status-succeeds-without-sync-activity."""
from __future__ import annotations

import re
import json
import time

from behavioral_harness import tags

CHECK = "get-resource-sync-status-succeeds-without-sync-activity"
GROUP = "sync-configuration"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceSyncStatus succeeds without DesiredState or LatestSync both for a configured resource that
    never synced and for a never-configured name, while GetSyncConfiguration fails on the latter with
    ResourceNotFoundException.
    """
    cc = ctx.client("codestar-connections")

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32], ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    role_arn = _create_sync_role(ctx)
    configured_resource = ctx.unique_name("sim2real-res-")
    _create_sync_configuration_retrying(
        cc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=configured_resource,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )
    ctx.on_cleanup(
        lambda: cc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=configured_resource)
    )

    configured_status = cc.get_resource_sync_status(
        ResourceName=configured_resource, SyncType="CFN_STACK_SYNC"
    )
    assert not configured_status.get("DesiredState"), configured_status
    assert not configured_status.get("LatestSync"), configured_status

    never_configured_resource = ctx.unique_name("sim2real-unrelated-")
    unconfigured_status = cc.get_resource_sync_status(
        ResourceName=never_configured_resource, SyncType="CFN_STACK_SYNC"
    )
    assert not unconfigured_status.get("DesiredState"), unconfigured_status
    assert not unconfigured_status.get("LatestSync"), unconfigured_status

    # positive control: GetSyncConfiguration DOES distinguish the two -- it is fully
    # reachable for the configured resource...
    got = cc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=configured_resource)[
        "SyncConfiguration"
    ]
    assert got["ResourceName"] == configured_resource

    # ...and rejects the never-configured one.
    code, message = _error_code(
        lambda: cc.get_sync_configuration(
            SyncType="CFN_STACK_SYNC", ResourceName=never_configured_resource
        )
    )
    assert code == "ResourceNotFoundException", code
    expected_message = f"CloudFormation Stack Sync configuration not found for accountId: {ctx.account} and configTarget: cfn-stack-sync/arn:aws:cloudformation:{ctx.region}:{ctx.account}:stack/{never_configured_resource}" + _suffix(404, "ResourceNotFoundException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


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


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_repository_link(cc, link_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_repository_link(RepositoryLinkId=link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_sync_role(ctx) -> str:
    """A role trusted by the Git-sync service principal, with the CloudFormation
    permissions the sync engine documents needing. CreateSyncConfiguration can
    transiently AccessDeny while a brand-new role is still propagating, so the
    caller should use `_create_sync_configuration_retrying` below.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-syncrole-")
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"][
        "Arn"
    ]
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
    # LIFO cleanup removes the inline policy before DeleteRole, which refuses a role that has one.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sync-permissions"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _create_sync_configuration_retrying(cc, *, timeout_s: float = 45.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return cc.create_sync_configuration(**kwargs)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"CreateSyncConfiguration never succeeded past IAM propagation: {last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
