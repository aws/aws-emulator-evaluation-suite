"""create-sync-configuration-with-publish-deployment-status-persisted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-sync-configuration-with-publish-deployment-status-persisted"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The optional PublishDeploymentStatus and TriggerResourceUpdateOn enum fields supplied
    to CreateSyncConfiguration are persisted and returned unchanged by GetSyncConfiguration.
    """
    cc = ctx.client("codestar-connections")

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner,
        RepositoryName=repo,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    role_arn = _create_sync_role(ctx)
    resource_name = ctx.unique_name("sim2real-res-")
    created = _create_sync_configuration_retrying(
        cc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
        PublishDeploymentStatus="ENABLED",
        TriggerResourceUpdateOn="FILE_CHANGE",
    )["SyncConfiguration"]
    ctx.on_cleanup(
        lambda: cc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )

    assert created["PublishDeploymentStatus"] == "ENABLED", (
        f"expected PublishDeploymentStatus=ENABLED, got {created['PublishDeploymentStatus']!r}"
    )
    assert created["TriggerResourceUpdateOn"] == "FILE_CHANGE", (
        f"expected TriggerResourceUpdateOn=FILE_CHANGE, got {created['TriggerResourceUpdateOn']!r}"
    )

    got = cc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)[
        "SyncConfiguration"
    ]
    assert got["PublishDeploymentStatus"] == "ENABLED", (
        f"GetSyncConfiguration: expected PublishDeploymentStatus=ENABLED, "
        f"got {got['PublishDeploymentStatus']!r}"
    )
    assert got["TriggerResourceUpdateOn"] == "FILE_CHANGE", (
        f"GetSyncConfiguration: expected TriggerResourceUpdateOn=FILE_CHANGE, "
        f"got {got['TriggerResourceUpdateOn']!r}"
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
