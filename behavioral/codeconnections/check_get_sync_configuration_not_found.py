"""get-sync-configuration-not-found."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sync-configuration-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected rejection, but the call succeeded: {result!r}")


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
    """An execution role real CodeConnections accepts on CreateSyncConfiguration."""
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
    """CreateSyncConfiguration briefly rejects with AccessDeniedException while the
    freshly created role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return cc.create_sync_configuration(**kwargs)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"CreateSyncConfiguration never succeeded past IAM propagation: {last_code}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSyncConfiguration for a resource with no sync configuration raises ResourceNotFoundException,
    while a created sync configuration reads back."""
    cc = ctx.client("codeconnections")

    # positive control: GetSyncConfiguration succeeds for a ResourceName that has one
    role_arn = _create_sync_role(ctx)
    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-conn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=ctx.unique_name("s2rowner")[:32],
        RepositoryName=ctx.unique_name("s2rrepo")[:32],
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))

    live_resource_name = ctx.unique_name("sim2realsync-live-")
    _create_sync_configuration_retrying(
        cc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=live_resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )
    ctx.on_cleanup(
        lambda: cc.delete_sync_configuration(
            SyncType="CFN_STACK_SYNC", ResourceName=live_resource_name
        )
    )
    live = cc.get_sync_configuration(ResourceName=live_resource_name, SyncType="CFN_STACK_SYNC")[
        "SyncConfiguration"
    ]
    assert live["ResourceName"] == live_resource_name, (
        "positive control: expected ResourceName=" + live_resource_name
        + ", got " + str(live["ResourceName"])
    )

    # negative: a ResourceName that never had a sync configuration is rejected
    absent_resource_name = ctx.unique_name("s2rsync-absent-")
    code, message = _error_code(
        lambda: cc.get_sync_configuration(
            ResourceName=absent_resource_name, SyncType="CFN_STACK_SYNC"
        )
    )
    assert code == "ResourceNotFoundException", (
        "expected ResourceNotFoundException, actual_code=" + str(code)
    )
    expected_message = f"CloudFormation Stack Sync configuration not found for accountId: {ctx.account} and configTarget: cfn-stack-sync/arn:aws:cloudformation:{ctx.region}:{ctx.account}:stack/{absent_resource_name}" + _suffix(404, "ResourceNotFoundException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
