"""create-user-unicode-homedirectory-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-unicode-homedirectory-round-trip"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A HomeDirectoryMappings entry/target containing non-ASCII unicode characters survives
    CreateUser and is returned byte-for-byte unchanged by DescribeUser."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    entry = "/donn\u00e9es-t\u00e9st-\U0001F4C1-\u6587\u4ef6\u5939"
    target = "/sim2real-bucket/d\u00e9j\u00e0-vu/\u30c6\u30b9\u30c8"
    username = ctx.unique_name("sim2realuser")

    _retry_role_propagation(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=username,
            Role=role_arn,
            HomeDirectoryType="LOGICAL",
            HomeDirectoryMappings=[{"Entry": entry, "Target": target, "Type": "DIRECTORY"}],
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    described = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    mappings = described["HomeDirectoryMappings"]
    assert len(mappings) == 1
    assert mappings[0]["Entry"] == entry, f"Entry mangled: {mappings[0]['Entry']!r} != {entry!r}"
    assert mappings[0]["Target"] == target, f"Target mangled: {mappings[0]['Target']!r} != {target!r}"


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            }
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRequestException", "AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
