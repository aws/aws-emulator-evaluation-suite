"""delete-sync-configuration-removes-it."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-sync-configuration-removes-it"
GROUP = "sync-configuration"
SERVICES = ["codestar-connections"]


def _error(fn):
    """Call fn(); return its error dict, the Request ID in the message masked. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        error = dict(e.response["Error"])
        error["Message"] = _mask_request_id(error.get("Message", ""))
        return error
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    # DeleteRole fails (DeleteConflict) while an inline policy is still attached, and
    # ctx.on_cleanup swallows that silently, leaking the role every run. Registered after the
    # delete_role cleanup so LIFO order detaches the policy first.
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSyncConfiguration removes it without touching the repository link."""
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

    csc.delete_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)

    err = _error(
        lambda: csc.get_sync_configuration(SyncType="CFN_STACK_SYNC", ResourceName=resource_name)
    )
    assert err["Code"] == "ResourceNotFoundException", err
    expected_message = (
        f"CloudFormation Stack Sync configuration not found for accountId: {ctx.account} and "
        f"configTarget: cfn-stack-sync/arn:aws:cloudformation:{ctx.region}:{ctx.account}:stack/"
        f"{resource_name} (Service: CodeConnections; Status Code: 404; Error Code: "
        "ResourceNotFoundException; Request ID: <id>; Proxy: null)"
    )
    assert err["Message"] == expected_message, (
        f"the refusal said {err['Message']!r}, expected {expected_message!r}"
    )

    # A mutation on the now-dead sync configuration also fails, not just the read: real AWS
    # rejects UpdateSyncConfiguration on a missing ResourceName as an invalid input, not a
    # not-found (GetSyncConfiguration and UpdateSyncConfiguration report
    # the same absence with different codes).
    update_err = _error(
        lambda: csc.update_sync_configuration(
            ResourceName=resource_name, SyncType="CFN_STACK_SYNC", Branch="develop"
        )
    )
    assert update_err["Code"] == "InvalidInputException", update_err
    assert update_err["Message"] == f"Sync Configuration for Resource {resource_name} was not found", (
        update_err["Message"]
    )

    # The repository link itself is untouched by deleting the sync configuration.
    link = csc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert link["RepositoryLinkId"] == link_id, (link_id, link["RepositoryLinkId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
