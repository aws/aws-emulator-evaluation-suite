"""delete-repository-link-blocked-by-active-sync-configuration-rejected."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-link-blocked-by-active-sync-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


def _error(fn):
    """Call fn(); return the (code, message) it is refused with, the Request ID masked.
    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], _mask_request_id(error.get("Message", ""))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _tolerate_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_sync_role(ctx) -> str:
    """An execution role CodeConnections accepts on CreateSyncConfiguration."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-syncrole-")[:64]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    permissions = {
        "Version": "2012-10-17",
        "Statement": [
            {
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
                "Effect": "Allow",
                "Action": ["events:PutRule", "events:PutTargets"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"events:ManagedBy": ["cloudformation.sync.codeconnections.amazonaws.com"]}
                },
            },
            {"Effect": "Allow", "Action": "events:DescribeRule", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sync-permissions", PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sync-permissions"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _create_sync_configuration_retrying(cc, *, timeout_s: float = 60.0, **kwargs):
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
    """DeleteRepositoryLink on a link a sync configuration references raises
    SyncConfigurationStillExistsException and the link stays; after the sync configuration is deleted
    the same call removes it."""
    cc = ctx.client("codeconnections")
    role_arn = _create_sync_role(ctx)

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-conn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    owner_id = ctx.unique_name("s2rowner")[:32]
    repo_name = ctx.unique_name("s2rrepo")[:32]
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=repo_name,
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _tolerate_not_found(lambda: cc.delete_repository_link(RepositoryLinkId=link_id)))

    resource_name = ctx.unique_name("sim2realsync-")
    _create_sync_configuration_retrying(
        cc,
        Branch="main",
        ConfigFile="template.yaml",
        RepositoryLinkId=link_id,
        ResourceName=resource_name,
        RoleArn=role_arn,
        SyncType="CFN_STACK_SYNC",
    )
    ctx.on_cleanup(
        lambda: _tolerate_not_found(
            lambda: cc.delete_sync_configuration(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")
        )
    )

    code, message = _error(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))
    assert code == "SyncConfigurationStillExistsException", (
        f"expected DeleteRepositoryLink to be blocked by the active sync configuration with "
        f"SyncConfigurationStillExistsException, got {code!r}"
    )
    expected_message = f"Cfn stack sync configurations still exist for repository {owner_id}/{repo_name}. Please delete them before retrying." + _suffix(409, "ResourceStillExistsException")
    assert message == expected_message, (
        f"the refusal said {message!r}, expected {expected_message!r}"
    )

    # effect absent: the repository link is still there
    still_there = cc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert still_there["RepositoryLinkId"] == link_id, (
        f"expected the blocked delete to leave the repository link readable with id {link_id!r}, "
        f"got {still_there['RepositoryLinkId']!r}"
    )

    # positive control: remove the blocker, then the same delete call succeeds
    cc.delete_sync_configuration(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")
    cc.delete_repository_link(RepositoryLinkId=link_id)
    final_code, final_code_message = _error(lambda: cc.get_repository_link(RepositoryLinkId=link_id))
    assert final_code == "ResourceNotFoundException", (
        f"expected the identical DeleteRepositoryLink call to succeed once its sync configuration "
        f"blocker is removed, and the link to read back not-found; got {final_code!r}"
    )
    expected_final_code_message = f"Repository not found for accountId: {ctx.account} and uuid: {link_id}" + _suffix(404, "ResourceNotFoundException")
    assert final_code_message == expected_final_code_message, (
        f"the refusal said {final_code_message!r}, expected {expected_final_code_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
