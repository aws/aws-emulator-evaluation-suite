"""list-sync-configurations-reflects-created-config."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-sync-configurations-reflects-created-config"
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


def _list_all_sync_configurations(csc, **kwargs) -> list[dict]:
    configs: list[dict] = []
    token = None
    while True:
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = csc.list_sync_configurations(**page_kwargs)
        configs.extend(resp.get("SyncConfigurations", []))
        token = resp.get("NextToken")
        if not token:
            break
    return configs


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSyncConfigurations for a repository link includes a freshly created config."""
    csc = ctx.client("codestar-connections")
    role_arn = _create_sync_role(ctx)

    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"),
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    owner_id = "sim2real-owner"
    repository_name = ctx.unique_name("sim2real-behav-repo-")
    link_id = csc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=repository_name,
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

    configs = _list_all_sync_configurations(csc, RepositoryLinkId=link_id, SyncType="CFN_STACK_SYNC")
    matches = [c for c in configs if c["ResourceName"] == resource_name]
    assert len(matches) == 1, f"expected exactly one match for {resource_name!r}, got {matches}"
    listed = matches[0]
    assert listed["Branch"] == "main", f"expected Branch='main', got {listed.get('Branch')!r}"
    assert listed["RoleArn"] == role_arn, f"expected RoleArn={role_arn!r}, got {listed.get('RoleArn')!r}"
    assert listed["ConfigFile"] == "template.yaml", (
        f"expected ConfigFile='template.yaml', got {listed.get('ConfigFile')!r}"
    )
    assert listed["ProviderType"] == "GitHub", (
        f"expected ProviderType='GitHub', got {listed.get('ProviderType')!r}"
    )
    assert listed["OwnerId"] == owner_id, f"expected OwnerId={owner_id!r}, got {listed.get('OwnerId')!r}"
    assert listed["RepositoryName"] == repository_name, (
        f"expected RepositoryName={repository_name!r}, got {listed.get('RepositoryName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
