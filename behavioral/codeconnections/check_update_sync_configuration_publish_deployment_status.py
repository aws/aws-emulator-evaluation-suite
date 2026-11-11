"""update-sync-configuration-publish-deployment-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-sync-configuration-publish-deployment-status"
GROUP = "state"
SERVICES = ["codeconnections", "iam"]

_SYNC_PRINCIPAL = "cloudformation.sync.codeconnections.amazonaws.com"


def _sync_role(ctx) -> str:
    """Creates the role CFN stack sync assumes, and registers its removal."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ccsync-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": _SYNC_PRINCIPAL}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "events:PutRule",
                    "events:PutTargets",
                    "events:DescribeRule",
                    "events:DeleteRule",
                    "events:RemoveTargets",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-sync", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-sync")
    )
    return role_arn


def _create_sync_configuration(cc, **kwargs) -> dict:
    """CreateSyncConfiguration, retrying only while the new role's IAM trust propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            return cc.create_sync_configuration(**kwargs)["SyncConfiguration"]
        except ClientError as err:
            if (
                err.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
        time.sleep(5)


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSyncConfiguration changes PublishDeploymentStatus from ENABLED to DISABLED, and
    GetSyncConfiguration reads back DISABLED with the branch, config file, link and role unchanged."""
    cc = ctx.client("codeconnections")
    role_arn = _sync_role(ctx)

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2realcc-")[-32:], ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: cc.delete_connection(ConnectionArn=conn_arn)))

    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=ctx.unique_name("s2rowner")[:64],
        RepositoryName=ctx.unique_name("s2rrepo")[:64],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: cc.delete_repository_link(RepositoryLinkId=link_id)))

    resource_name = ctx.unique_name("s2rsync")
    created = _create_sync_configuration(
        cc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
        PublishDeploymentStatus="ENABLED",
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: cc.delete_sync_configuration(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")
        )
    )
    assert created["PublishDeploymentStatus"] == "ENABLED", repr(created)

    updated = cc.update_sync_configuration(
        ResourceName=resource_name, SyncType="CFN_STACK_SYNC", PublishDeploymentStatus="DISABLED"
    )["SyncConfiguration"]
    assert updated["PublishDeploymentStatus"] == "DISABLED", repr(updated)

    refreshed = cc.get_sync_configuration(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")[
        "SyncConfiguration"
    ]
    assert refreshed["PublishDeploymentStatus"] == "DISABLED", repr(refreshed)
    assert refreshed["Branch"] == "main", repr(refreshed)
    assert refreshed["ConfigFile"] == "template.yaml", repr(refreshed)
    assert refreshed["RepositoryLinkId"] == link_id, repr(refreshed)
    assert refreshed["RoleArn"] == role_arn, repr(refreshed)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
