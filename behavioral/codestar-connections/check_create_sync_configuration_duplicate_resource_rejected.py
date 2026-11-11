"""create-sync-configuration-duplicate-resource-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sync-configuration-duplicate-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


def _duplicate_create_error_code(csc, *, timeout_s: float = 45.0, **kwargs) -> tuple[str, str]:
    """Probe the duplicate-key rejection and return its (code, message), the Request ID masked, retrying only past IAM's own AssumeRole propagation
    delay (the same transient AccessDeniedException the positive-control retry absorbs) so the
    check measures the duplicate-key contract rather than a propagation race.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            result = csc.create_sync_configuration(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException":
                time.sleep(3)
                continue
            return code, _mask_request_id(e.response["Error"].get("Message", ""))
        raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")
    raise AssertionError("duplicate-create probe never got past IAM propagation (AccessDeniedException)")


_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]+;")


def _mask_request_id(message: str) -> str:
    """AWS appends a per-request backend Request ID to every CodeConnections refusal; mask it."""
    return _REQUEST_ID.sub("Request ID: <id>;", message)


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
    """A second CreateSyncConfiguration for the same ResourceName and SyncType fails with
    ResourceAlreadyExistsException and its exact message without changing the original Branch, while another
    ResourceName is created.
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

    code, message = _duplicate_create_error_code(
        csc,
        Branch="develop",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )
    assert code == "ResourceAlreadyExistsException", code
    expected_message = (
        "CfnStackSyncConfiguration already exists. (Service: CodeConnections; Status Code: 409; "
        "Error Code: ResourceAlreadyExistsException; Request ID: <id>; Proxy: null)"
    )
    assert message == expected_message, f"the refusal said {message!r}, expected {expected_message!r}"

    # Effect absent: the original Branch value survives untouched.
    fetched = csc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)[
        "SyncConfiguration"
    ]
    assert fetched["Branch"] == "main"

    # Positive control: a different ResourceName still succeeds.
    other_resource_name = ctx.unique_name("sim2real-behav-stack2-")
    other = _create_sync_configuration_retrying(
        csc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=other_resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )["SyncConfiguration"]
    ctx.on_cleanup(
        lambda: csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=other_resource_name)
    )
    assert other["ResourceName"] == other_resource_name

    # Terminal assertion is an independent read (different operation than the mutation above).
    other_fetched = csc.get_sync_configuration(
        SyncType="CFN_STACK_SYNC", ResourceName=other_resource_name
    )["SyncConfiguration"]
    assert other_fetched["Branch"] == "main"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
