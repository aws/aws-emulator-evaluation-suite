"""update-sync-blocker-nonexistent-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-sync-blocker-nonexistent-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSyncBlocker with a made-up blocker Id on an existing sync configuration fails with
    SyncBlockerDoesNotExistException and its exact message, while GetSyncConfiguration reaches the
    configuration.
    """
    csc = ctx.client("codestar-connections")
    role_arn = _create_sync_role(ctx)

    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    link_id = csc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId="sim2real-owner",
        RepositoryName=ctx.unique_name("sim2real-behav-repo-"),
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: csc.delete_repository_link(RepositoryLinkId=link_id))

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
    ctx.on_cleanup(
        lambda: csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )

    blocker_id = "sim2real-nonexistent-blocker-id"
    err = _error(
        lambda: csc.update_sync_blocker(
            Id=blocker_id,
            SyncType="CFN_STACK_SYNC",
            ResourceName=resource_name,
            ResolvedReason="closing a blocker that was never active",
        )
    )
    assert err["Code"] == "SyncBlockerDoesNotExistException", (
        f"expected SyncBlockerDoesNotExistException for a made-up blocker Id, got {err!r}"
    )
    # AWS's message ends with a trailing space.
    assert err["Message"] == f"Sync blocker with id {blocker_id} does not exist ", err["Message"]

    # Positive control: the resource/sync-type pair itself is valid and reachable.
    fetched = csc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)[
        "SyncConfiguration"
    ]
    assert fetched["ResourceName"] == resource_name, (
        f"expected GetSyncConfiguration to still reach {resource_name!r} after the rejected "
        f"UpdateSyncBlocker call, got {fetched.get('ResourceName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
