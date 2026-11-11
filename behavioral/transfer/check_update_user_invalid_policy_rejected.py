"""update-user-invalid-policy-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-invalid-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUser rejects a syntactically invalid session policy document with
    InvalidRequestException, leaves the user's Policy field untouched, and a
    subsequent well-formed policy update still succeeds and persists."""
    ctx.client("iam")
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx, "upduser")
    server_id = transfer.create_server(
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2real-upduser-")
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=role_arn,
        HomeDirectory="/sim2real-bucket/home",
        HomeDirectoryType="PATH",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    malformed_policy = '{"Version": "2012-10-17", "Statement": [ this is not json'
    code, message = _error(
        lambda: transfer.update_user(
            ServerId=server_id, UserName=user_name, Policy=malformed_policy
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "Policy is not a valid JSON document"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the malformed write must not have landed
    after_reject = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    rejected_policy = after_reject.get("Policy")
    assert rejected_policy != malformed_policy, (
        f"malformed Policy was persisted: {rejected_policy!r}"
    )
    assert not rejected_policy, f"expected no Policy after rejection, got {rejected_policy!r}"

    # positive control: a well-formed session policy on the same user still succeeds
    valid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowListingOfUserFolder",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::sim2real-bucket"],
                }
            ],
        }
    )
    transfer.update_user(ServerId=server_id, UserName=user_name, Policy=valid_policy)
    after_accept = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    assert after_accept["Policy"] == valid_policy, (
        f"expected persisted Policy {valid_policy!r}, got {after_accept.get('Policy')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_transfer_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-transfer-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
