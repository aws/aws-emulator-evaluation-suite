"""resource-policy-explicit-deny-blocks-access-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-explicit-deny-blocks-access-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit table resource-policy Deny blocks a role's GetItem with AccessDeniedException,
    although the same policy also Allows GetItem and the role has no identity policy of its own."""
    from botocore.exceptions import ClientError

    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _drop_table():
        # Right after DeleteResourcePolicy, DeleteTable briefly raises ResourceInUseException.
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            try:
                ddb.delete_table(TableName=table_name)
                return
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceInUseException":
                    raise
                time.sleep(5.0)
        ddb.delete_table(TableName=table_name)

    table_name = ctx.unique_name("sim2real-behav-rbp-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=resource_tags,
    )
    ctx.on_cleanup(_drop_table)
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    key = {"pk": {"S": "item-1"}}
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-1"}, "val": {"S": "before"}})

    # A bare IAM role with NO identity-based policies attached: any DynamoDB
    # access it gets can only come from the table's resource-based policy.
    role_name = ctx.unique_name("sim2real-behav-rbp-role-")
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
        Tags=resource_tags,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    def _put_resource_policy_with_retry(policy_doc):
        """A brand-new IAM role is not immediately resolvable as a resource-policy
        Principal (IAM's own eventual consistency) -- retry past the transient
        'Invalid principal in policy' ValidationException."""
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

    def _assume_role_client():
        deadline = time.monotonic() + 60.0
        last_err = None
        while time.monotonic() < deadline:
            try:
                creds = sts.assume_role(
                    RoleArn=role_arn, RoleSessionName="sim2real-behav-rbp"
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

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRolePutItem",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "dynamodb:PutItem",
                "Resource": table_arn,
            },
            {
                "Sid": "AllowRoleGetItem",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "dynamodb:GetItem",
                "Resource": table_arn,
            },
            {
                "Sid": "DenyRoleGetItem",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "dynamodb:GetItem",
                "Resource": table_arn,
            },
        ],
    }
    _put_resource_policy_with_retry(allow_policy)
    ctx.on_cleanup(lambda: ddb.delete_resource_policy(ResourceArn=table_arn))

    # One policy version holds Allow(PutItem), Allow(GetItem) and Deny(GetItem): only
    # explicit-Deny-overrides-Allow rejects GetItem, and one propagation wait covers all three.
    def _put_via_role(role_ddb):
        """'succeeded' once the role's PutItem is accepted, otherwise the refusal's error code."""
        try:
            role_ddb.put_item(
                TableName=table_name, Item={"pk": {"S": "item-1"}, "val": {"S": "written-by-role"}}
            )
            return "succeeded"
        except ClientError as err:
            return err.response["Error"]["Code"]

    def _get_via_role(role_ddb):
        """(code, message) of the role's refused GetItem; an accepted read fails the check."""
        try:
            role_ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        raise AssertionError("expected the role's GetItem to be denied, but it succeeded")

    role_ddb = _assume_role_client()

    # Positive control: PutItem is granted only by this policy, so success proves it is live.
    put_code = "not-yet-tried"
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        put_code = _put_via_role(role_ddb)
        if put_code == "succeeded":
            break
        time.sleep(5.0)
    assert put_code == "succeeded", f"expected the resource-policy Allow(PutItem) to take effect, saw {put_code!r}"

    # Same policy version, so the Deny must already be enforced despite the live Allow(GetItem).
    get_code, get_message = _get_via_role(role_ddb)
    assert get_code == "AccessDeniedException", f"expected AccessDeniedException, saw {get_code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-rbp is not "
        f"authorized to perform: dynamodb:GetItem on resource: {table_arn} with an explicit deny "
        "in a resource-based policy"
    )
    assert get_message == expected, f"unexpected message {get_message!r}"

    # The owner's own credentials are unaffected; the role's PutItem overwrote the value.
    resp2 = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)
    actual_val = resp2.get("Item", {}).get("val", {}).get("S")
    assert actual_val == "written-by-role", (
        f"expected the owner's own read to see the role's PutItem-written value "
        f"'written-by-role' (unaffected by the resource policy), saw {actual_val!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


