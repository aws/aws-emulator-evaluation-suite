"""deploy-transfer-user-update-adds-key-and-tags-then-rename-replaces-it."""
from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-transfer-user-update-adds-key-and-tags-then-rename-replaces-it"
GROUP = "deploy"
SERVICES = ["cloudformation", "transfer"]

_STACK_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)

_TRUST_TRANSFER = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def expect_error(fn, code: str, message: str) -> None:
    """Call ``fn`` and require the exact ``(code, message)``; raise if it succeeds instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected error {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected error {(code, message)!r}, but the call succeeded: {result!r}")


def _generate_ssh_public_key() -> str:
    """A freshly generated 2048-bit RSA key pair's public half, in OpenSSH wire format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return body.decode("ascii")


def _poll_stack_status(cf, stack_id: str, deadline: float) -> str:
    """Poll DescribeStacks until a terminal StackStatus; raise on timeout, never on a ClientError."""
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after its deadline")
        time.sleep(3)


def _stack_outputs(cf, stack_id: str) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack_and_confirm(cf, stack_id: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; a second call on an absent stack is a no-op."""
    try:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except cf.exceptions.ClientError as exc:
        if "does not exist" in (exc.response["Error"].get("Message") or ""):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    final = _poll_stack_status(cf, stack_id, time.monotonic() + timeout_s)
    assert final == "DELETE_COMPLETE", f"stack {stack_id} ended {final!r} instead of DELETE_COMPLETE"


def _delete_server_and_confirm(transfer, server_id: str) -> None:
    try:
        transfer.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ResourceNotFoundException":
            return
        raise


def _wait_server_online(transfer, server_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state == "ONLINE":
            return
        assert state in ("STARTING", "OFFLINE"), f"server {server_id} entered {state!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"server {server_id} still {state!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _user_names(transfer, server_id: str) -> set:
    names = set()
    for page in transfer.get_paginator("list_users").paginate(ServerId=server_id):
        names |= {u["UserName"] for u in page["Users"]}
    return names


def _user_template(server_id: str, username: str, home_suffix: str, ssh_keys: list, user_tags: list) -> str:
    home_directory = {"Fn::Sub": "/${HomeBucket}" + (f"/{home_suffix}" if home_suffix else "")}
    properties = {
        "ServerId": server_id,
        "UserName": username,
        "Role": {"Fn::GetAtt": ["UserRole", "Arn"]},
        "HomeDirectory": home_directory,
        "HomeDirectoryType": "PATH",
    }
    if ssh_keys:
        properties["SshPublicKeys"] = ssh_keys
    if user_tags:
        properties["Tags"] = user_tags
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "HomeBucket": {"Type": "AWS::S3::Bucket"},
                "UserRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": _TRUST_TRANSFER,
                        "Policies": [
                            {
                                "PolicyName": "home-directory-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "s3:ListBucket",
                                            "Resource": {"Fn::GetAtt": ["HomeBucket", "Arn"]},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject", "s3:PutObject"],
                                            "Resource": {"Fn::Sub": "${HomeBucket.Arn}/*"},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "User": {"Type": "AWS::Transfer::User", "Properties": properties},
            },
            "Outputs": {
                "HomeDirectory": {"Value": home_directory},
                "RoleArn": {"Value": {"Fn::GetAtt": ["UserRole", "Arn"]}},
            },
        }
    )


_USER_GONE = ("ResourceNotFoundException", "Unknown user")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-managed AWS::Transfer::User reflects an UpdateStack that changes its
    HomeDirectory and adds SshPublicKeys and Tags, and a later UpdateStack that changes only its
    UserName replaces it: the old name is refused and the new one reads back the same settings.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-transfer-user.html
    """
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")

    server_name = ctx.unique_name("sim2real-cfnsftp-")
    server_id = transfer.create_server(
        Protocols=["SFTP"],
        EndpointType="PUBLIC",
        IdentityProviderType="SERVICE_MANAGED",
        Tags=[{"Key": "sim2real", "Value": server_name}],
    )["ServerId"]
    ctx.on_cleanup(lambda sid=server_id: _delete_server_and_confirm(transfer, sid))
    _wait_server_online(transfer, server_id)

    stack_name = ctx.unique_name("sim2real-cfntru-")
    username1 = ctx.unique_name("sim2real-sftpuser-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_user_template(server_id, username1, "", [], []),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda sid=stack_id: _delete_stack_and_confirm(cfn, sid))

    status = _poll_stack_status(cfn, stack_id, time.monotonic() + 300.0)
    assert status == "CREATE_COMPLETE", f"stack {stack_id} ended {status!r}, expected CREATE_COMPLETE"

    outputs = _stack_outputs(cfn, stack_id)
    initial_home, role_arn = outputs["HomeDirectory"], outputs["RoleArn"]

    described = transfer.describe_user(ServerId=server_id, UserName=username1)["User"]
    got = (described["UserName"], described["Role"], described["HomeDirectory"], described["HomeDirectoryType"])
    assert got == (username1, role_arn, initial_home, "PATH"), (
        f"DescribeUser after create read {got!r}, expected "
        f"{(username1, role_arn, initial_home, 'PATH')!r}"
    )
    assert _user_names(transfer, server_id) == {username1}, (
        f"ListUsers on server {server_id!r} did not hold exactly the created user {username1!r}"
    )

    pubkey = _generate_ssh_public_key()
    extra_tag = {"Key": "Project", "Value": "example-sftp"}
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_user_template(server_id, username1, "updated", [pubkey], [extra_tag]),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _poll_stack_status(cfn, stack_id, time.monotonic() + 300.0)
    assert status == "UPDATE_COMPLETE", f"first update ended {status!r}, expected UPDATE_COMPLETE"

    updated_home = _stack_outputs(cfn, stack_id)["HomeDirectory"]
    assert updated_home == f"{initial_home}/updated", (
        f"HomeDirectory after the update is {updated_home!r}, expected {initial_home + '/updated'!r}"
    )

    described = transfer.describe_user(ServerId=server_id, UserName=username1)["User"]
    assert described["HomeDirectory"] == updated_home, (
        f"DescribeUser's HomeDirectory is {described['HomeDirectory']!r} after the update, "
        f"expected {updated_home!r}"
    )
    key_bodies = [k["SshPublicKeyBody"] for k in described.get("SshPublicKeys", [])]
    assert key_bodies == [pubkey], f"DescribeUser's SshPublicKeys bodies are {key_bodies!r}, expected [pubkey]"
    got_tags = {(t["Key"], t["Value"]) for t in described.get("Tags", [])}
    want_tags = {
        (extra_tag["Key"], extra_tag["Value"]),
        ("aws:cloudformation:stack-name", stack_name),
        ("aws:cloudformation:stack-id", stack_id),
        ("aws:cloudformation:logical-id", "User"),
    }
    assert got_tags == want_tags, f"DescribeUser's Tags are {got_tags!r}, expected exactly {want_tags!r}"

    username2 = ctx.unique_name("sim2real-sftpuser-")
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_user_template(server_id, username2, "updated", [pubkey], [extra_tag]),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _poll_stack_status(cfn, stack_id, time.monotonic() + 300.0)
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}, expected UPDATE_COMPLETE"

    expect_error(lambda: transfer.describe_user(ServerId=server_id, UserName=username1), *_USER_GONE)

    described = transfer.describe_user(ServerId=server_id, UserName=username2)["User"]
    got = (described["UserName"], described["HomeDirectory"], described["HomeDirectoryType"])
    assert got == (username2, updated_home, "PATH"), (
        f"DescribeUser on the renamed user read {got!r}, expected {(username2, updated_home, 'PATH')!r}"
    )
    key_bodies = [k["SshPublicKeyBody"] for k in described.get("SshPublicKeys", [])]
    assert key_bodies == [pubkey], (
        f"the renamed user's SshPublicKeys bodies are {key_bodies!r}, expected the same key [pubkey]"
    )
    assert _user_names(transfer, server_id) == {username2}, (
        f"ListUsers on server {server_id!r} after the rename did not hold exactly the new name "
        f"{username2!r}"
    )

    _delete_stack_and_confirm(cfn, stack_id)
    assert _user_names(transfer, server_id) == set(), (
        f"ListUsers on server {server_id!r} still lists a user after the stack reached DELETE_COMPLETE"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
