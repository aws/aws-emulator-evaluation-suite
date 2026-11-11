"""update-user-malformed-role-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUser with a syntactically invalid IAM role ARN for Role is rejected with
    InvalidRequestException, and the user's previously-persisted Role is left
    unchanged rather than being overwritten with the malformed value."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = transfer.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2reala").replace("-", "")[:32]
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    code, message = _error(
        lambda: transfer.update_user(
            ServerId=server_id, UserName=user_name, Role="not-a-valid-role-arn"
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Invalid Role ARN", f"expected message 'Invalid Role ARN', got {message!r}"

    # Effect absent: the user's Role still reflects the original, valid value.
    described = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    assert described["Role"] == role_arn, "malformed Role was persisted despite rejection"

    # Positive control: a syntactically valid new Role ARN is accepted and persisted.
    other_role_arn = _create_transfer_role(ctx)
    transfer.update_user(ServerId=server_id, UserName=user_name, Role=other_role_arn)
    described_after = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    assert described_after["Role"] == other_role_arn, (
        f"expected persisted Role {other_role_arn}, got {described_after['Role']!r}"
    )


def _create_transfer_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
