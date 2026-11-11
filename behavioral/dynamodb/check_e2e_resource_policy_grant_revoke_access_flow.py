"""e2e-resource-policy-grant-revoke-access-flow."""
from __future__ import annotations

import json
import time

CHECK = "e2e-resource-policy-grant-revoke-access-flow"
GROUP = "e2e"
SERVICES = ["dynamodb"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no identity-based policy is denied GetItem; a PutResourcePolicy grant lets it
    read the item, and DeleteResourcePolicy revokes it with the same denial message, while the
    table owner can still read the unchanged item afterwards."""
    from botocore.exceptions import ClientError

    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-behav-rbp2-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    key = {"pk": {"S": "grant-revoke-item"}}
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "grant-revoke-item"}, "val": {"S": "secret"}})

    role_name = ctx.unique_name("sim2real-behav-rbp2-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    def _assume_role_client():
        deadline = time.monotonic() + 60.0
        last_err = None
        while time.monotonic() < deadline:
            try:
                creds = sts.assume_role(
                    RoleArn=role_arn, RoleSessionName="sim2real-behav-rbp2"
                )["Credentials"]
                return ctx.client(
                    "dynamodb",
                    creds={
                        "aws_access_key_id": creds["AccessKeyId"],
                        "aws_secret_access_key": creds["SecretAccessKey"],
                        "aws_session_token": creds["SessionToken"],
                    },
                )
            except Exception as err:  # noqa: BLE001
                last_err = err
                time.sleep(3.0)
        raise AssertionError(f"could not assume freshly-created role in time: {last_err!r}")

    def _get_via_role(role_ddb):
        try:
            resp = role_ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)
            return None, resp
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")

    def _put_resource_policy_with_retry(policy_doc):
        """Retry the transient invalid-principal ValidationException while a new role propagates."""
        deadline = time.monotonic() + 60.0
        last_err = None
        while time.monotonic() < deadline:
            try:
                ddb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(policy_doc))
                return
            except ClientError as err:
                code = err.response["Error"]["Code"]
                msg = err.response["Error"].get("Message", "")
                if code == "ValidationException" and "principal" in msg.lower():
                    last_err = err
                    time.sleep(3.0)
                    continue
                raise
        raise AssertionError(f"principal never became resolvable in time: {last_err!r}")

    role_ddb = _assume_role_client()

    pre_grant_code, pre_grant_message = _get_via_role(role_ddb)
    assert pre_grant_code == "AccessDeniedException", (
        f"expected AccessDeniedException before any grant, saw {pre_grant_code!r}"
    )
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-rbp2"
    expected_denial = (
        f"User: {session_arn} is not authorized to perform: dynamodb:GetItem on resource: "
        f"{table_arn} because no identity-based policy allows the dynamodb:GetItem action"
    )
    assert pre_grant_message == expected_denial, (
        f"expected the denial message {expected_denial!r}, got {pre_grant_message!r}"
    )

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRoleGetItem",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "dynamodb:GetItem",
                "Resource": table_arn,
            }
        ],
    }
    _put_resource_policy_with_retry(allow_policy)
    policy_attached = True
    ctx.on_cleanup(lambda: ddb.delete_resource_policy(ResourceArn=table_arn) if policy_attached else None)

    # PutResourcePolicy is eventually consistent: poll until the grant is enforced.
    granted_item = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        code, resp = _get_via_role(role_ddb)
        if code is None:
            granted_item = resp.get("Item")
            break
        time.sleep(5.0)
    assert granted_item is not None, "resource-policy Allow(GetItem) never took effect on the role"
    assert granted_item.get("val", {}).get("S") == "secret", (
        f"expected item value 'secret' via the newly-granted role, got {granted_item!r}"
    )

    ddb.delete_resource_policy(ResourceArn=table_arn)
    policy_attached = False

    # Revocation is eventually consistent too: poll until GetItem is denied again.
    revoked_code, revoked_message = "not-yet-tried", None
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        revoked_code, revoked_message = _get_via_role(role_ddb)
        if revoked_code == "AccessDeniedException":
            break
        time.sleep(2)
    assert revoked_code == "AccessDeniedException", (
        f"expected access to be revoked after DeleteResourcePolicy, saw {revoked_code!r}"
    )
    expected_revoked = expected_denial
    assert revoked_message == expected_revoked, (
        f"expected the denial message {expected_revoked!r} after revocation, got {revoked_message!r}"
    )

    # Positive control: the owner's credentials are unaffected by the resource policy.
    owner_resp = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)
    assert owner_resp.get("Item", {}).get("val", {}).get("S") == "secret", (
        f"owner credentials (never touched by the resource policy) should still read the "
        f"unchanged item after the grant/revoke cycle, got {owner_resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
