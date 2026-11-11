"""user-home-directory-unicode-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "user-home-directory-unicode-preserved"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters in a user's HomeDirectoryMappings survive CreateUser and
    are returned unchanged by DescribeUser."""
    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    role_arn = _create_transfer_role(ctx, iam)
    server_id = transfer.create_server(
        Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    entry = "/"
    target = "/sim2real-bucket/ünïcödé-目录-📁/héllo wörld"

    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=role_arn,
        HomeDirectoryType="LOGICAL",
        HomeDirectoryMappings=[{"Entry": entry, "Target": target}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    described = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    mappings = described["HomeDirectoryMappings"]
    assert len(mappings) == 1, f"expected exactly one home directory mapping, got {mappings!r}"
    assert mappings[0]["Entry"] == entry, "HomeDirectoryMappings Entry was altered by the round trip"
    assert mappings[0]["Target"] == target, "HomeDirectoryMappings Target (unicode) was altered by the round trip"
    assert described["HomeDirectoryType"] == "LOGICAL", (
        f"expected HomeDirectoryType LOGICAL, got {described['HomeDirectoryType']!r}"
    )


def _create_transfer_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
