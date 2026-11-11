"""create-sync-configuration-success-fields."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sync-configuration-success-fields"
GROUP = "sync-configuration"
SERVICES = ["codestar-connections"]


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
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSyncConfiguration persists every input field, readable via Get."""
    csc = ctx.client("codestar-connections")
    role_arn = _create_sync_role(ctx)

    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"),
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    owner = "sim2real-owner"
    repo = ctx.unique_name("sim2real-behav-repo-")
    link_id = csc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner,
        RepositoryName=repo,
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: csc.delete_repository_link(RepositoryLinkId=link_id))

    resource_name = ctx.unique_name("sim2real-behav-stack-")
    created = _create_sync_configuration_retrying(
        csc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )["SyncConfiguration"]
    ctx.on_cleanup(
        lambda: csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )

    assert created["Branch"] == "main", f"expected Branch=main, got {created['Branch']!r}"
    assert created["ConfigFile"] == "template.yaml", (
        f"expected ConfigFile=template.yaml, got {created['ConfigFile']!r}"
    )
    assert created["ResourceName"] == resource_name, (
        f"expected ResourceName={resource_name!r}, got {created['ResourceName']!r}"
    )
    assert created["RoleArn"] == role_arn, f"expected RoleArn={role_arn!r}, got {created['RoleArn']!r}"
    assert created["SyncType"] == "CFN_STACK_SYNC", (
        f"expected SyncType=CFN_STACK_SYNC, got {created['SyncType']!r}"
    )
    assert created["RepositoryLinkId"] == link_id, (
        f"expected RepositoryLinkId={link_id!r}, got {created['RepositoryLinkId']!r}"
    )
    assert created["OwnerId"] == owner, f"expected OwnerId={owner!r}, got {created['OwnerId']!r}"
    assert created["RepositoryName"] == repo, (
        f"expected RepositoryName={repo!r}, got {created['RepositoryName']!r}"
    )
    assert created["ProviderType"] == "GitHub", (
        f"expected ProviderType=GitHub, got {created['ProviderType']!r}"
    )

    fetched = csc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)[
        "SyncConfiguration"
    ]
    assert fetched["Branch"] == "main", (
        f"GetSyncConfiguration: expected Branch=main, got {fetched['Branch']!r}"
    )
    assert fetched["RoleArn"] == role_arn, (
        f"GetSyncConfiguration: expected RoleArn={role_arn!r}, got {fetched['RoleArn']!r}"
    )
    assert fetched["RepositoryLinkId"] == link_id, (
        f"GetSyncConfiguration: expected RepositoryLinkId={link_id!r}, "
        f"got {fetched['RepositoryLinkId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
