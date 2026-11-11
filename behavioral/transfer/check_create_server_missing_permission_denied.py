"""create-server-missing-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-server-missing-permission-denied"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal whose policy explicitly denies transfer:CreateServer gets
    AccessDeniedException from CreateServer, not a 500 or a silent success."""
    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-behav-denyuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    allow_only_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "transfer:*", "Resource": "*"}],
    }
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "transfer:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "transfer:CreateServer", "Resource": "*"},
        ],
    }
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="deny-create-server",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName="deny-create-server")
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    limited = ctx.client(
        "transfer",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    before_ids = _server_ids(transfer)

    # wait out IAM's well-documented eventual-consistency window for new access keys by
    # polling the *allowed* ListServers call until the fresh credentials actually work
    _poll_until(
        lambda: _succeeds(lambda: limited.list_servers()),
        timeout_s=30.0,
        interval_s=2.0,
    )

    # A fresh access key can still be unrecognised by some endpoints right after one call
    # succeeded; retry only that credential-propagation code, bounded.
    denied_name = ctx.unique_name("sim2real-behav-denied-srv-")
    denied_tags = [{"Key": "Name", "Value": denied_name}]
    deadline = time.monotonic() + 30.0
    error = _client_error(ctx, transfer, lambda: limited.create_server(Tags=denied_tags))
    while error[0] == "UnrecognizedClientException" and time.monotonic() < deadline:
        time.sleep(2.0)
        error = _client_error(ctx, transfer, lambda: limited.create_server(Tags=denied_tags))
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"transfer:CreateServer on resource: arn:aws:transfer:{ctx.region}:{ctx.account}:server/* "
        "with an explicit deny in an identity-based policy"
    )
    assert error == ("AccessDeniedException", expected_message), error

    # effect absent: no new server was created under the denied identity
    created = _tagged_servers(transfer, _server_ids(transfer) - before_ids, "Name", denied_name)
    assert created == [], f"a server was created despite the explicit Deny: {created}"

    # restore: drop the Deny statement and drive the IDENTICAL call, from the SAME denied
    # identity, to success -- the beat that distinguishes "the Deny caused it" from any other
    # reason CreateServer might have failed for this principal.
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="deny-create-server",
        PolicyDocument=json.dumps(allow_only_doc),
    )
    restored: dict[str, str] = {}

    def _retry_create_after_restore() -> bool:
        try:
            restored["id"] = limited.create_server(
                Protocols=["SFTP"],
                IdentityProviderType="SERVICE_MANAGED",
                EndpointType="PUBLIC",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["ServerId"]
        except ClientError:
            return False
        return True

    _poll_until(_retry_create_after_restore, timeout_s=90.0, interval_s=3.0)
    restored_id = restored["id"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=restored_id))
    described_restored = transfer.describe_server(ServerId=restored_id)
    assert described_restored["Server"]["ServerId"] == restored_id, (
        f"removing the Deny statement must restore CreateServer for the identical denied "
        f"identity; expected {restored_id!r} to describe, got {described_restored['Server']!r}"
    )

    # positive control: the unrestricted caller can also create (and we tear down) a server
    good = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    server_id = good["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    described = transfer.describe_server(ServerId=server_id)
    assert described["Server"]["ServerId"] == server_id, (
        f"expected the unrestricted caller's DescribeServer to report {server_id!r}, got "
        f"{described['Server']!r}"
    )


def _succeeds(fn: Callable[[], Any]) -> bool:
    try:
        fn()
    except ClientError:
        return False
    return True


def _client_error(ctx, transfer, fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises (after
    registering cleanup of any server it created), so a target that ignores the Deny cannot read
    as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    server_id = result.get("ServerId")
    if server_id:
        ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _tagged_servers(transfer, ids, key, value) -> list[str]:
    """The servers among ids tagged key=value; one already deleted is not this check's, since
    this check deletes nothing before its teardown."""
    own = []
    for server_id in sorted(ids):
        try:
            server = transfer.describe_server(ServerId=server_id)["Server"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if {"Key": key, "Value": value} in server.get("Tags", []):
            own.append(server_id)
    return own


def _server_ids(transfer) -> set[str]:
    ids: set[str] = set()
    paginator = transfer.get_paginator("list_servers")
    for page in paginator.paginate():
        for server in page.get("Servers", []):
            ids.add(server["ServerId"])
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
