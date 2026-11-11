"""leading-keys-condition-scopes-query-to-the-callers-identity-id."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "leading-keys-condition-scopes-query-to-the-callers-identity-id"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity", "dynamodb"]

_DENIED_CODE = "AccessDeniedException"
_PROPAGATION_BUDGET_S = 300.0
_TABLE_BUDGET_S = 300.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet. Raises."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                },
            },
        }],
    })


def _set_roles(ci, pool_id, roles, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """A client on the target signed with the vended temporary credentials, never os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _query(client, table, user_id):
    """Query one partition; an absent Items key fails rather than defaulting."""
    return client.query(
        TableName=table,
        KeyConditionExpression="UserId = :u",
        ExpressionAttributeValues={":u": {"S": user_id}},
    )["Items"]


def _get_item(client, table, user_id, item_id):
    return client.get_item(
        TableName=table,
        Key={"UserId": {"S": user_id}, "ItemId": {"S": item_id}},
    )


def _refusal(fn):
    """Call fn() expecting a refusal; return (Code, Message). A success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _denial_message(session_arn, action, table_arn):
    return (
        f"User: {session_arn} is not authorized to perform: {action} on resource: {table_arn} "
        f"because no identity-based policy allows the {action} action"
    )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A LeadingKeys condition on the Cognito sub scopes each guest identity to its own partition.

    Both identities read their own item's bytes; both cross-partition directions are AccessDenied,
    through Query and GetItem.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html
    """
    ci = ctx.client("cognito-identity")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    account = ctx.client("sts").get_caller_identity()["Account"]

    table = ctx.unique_name("sim2real-behav-leadingkeys-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "UserId", "KeyType": "HASH"},
            {"AttributeName": "ItemId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "UserId", "AttributeType": "S"},
            {"AttributeName": "ItemId", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE",
        timeout_s=_TABLE_BUDGET_S,
        description=f"table {table} to become ACTIVE before any item is written",
    )
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table}"

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_lk_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_a = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_a]))
    identity_b = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_b]))
    assert identity_a != identity_b, (
        f"two GetId calls with no Logins must mint two distinct guest identities, both returned "
        f"{identity_a!r} — nothing below could then distinguish them"
    )

    item_id = "row-1"
    payloads = {
        identity_a: b"sim2real-lk-a-" + uuid.uuid4().bytes,
        identity_b: b"sim2real-lk-b-" + uuid.uuid4().bytes,
    }
    for owner, blob in payloads.items():
        ddb.put_item(
            TableName=table,
            Item={
                "UserId": {"S": owner},
                "ItemId": {"S": item_id},
                "blob": {"B": blob},
            },
        )

    role_name = ctx.unique_name("sim2real-behav-lk-role-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-behav-lk-grant"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                # No Scan: ForAllValues is true when the request carries no leading key, so a
                # Scan would be allowed by this condition.
                "Action": ["dynamodb:Query", "dynamodb:GetItem"],
                "Resource": table_arn,
                "Condition": {
                    "ForAllValues:StringEquals": {
                        "dynamodb:LeadingKeys": [
                            "${cognito-identity.amazonaws.com:sub}"
                        ]
                    }
                },
            }],
        }),
    )
    # Registered after delete_role so LIFO teardown drops the inline policy first.
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    _set_roles(ci, pool_id, {"unauthenticated": role_arn})

    def _session_for(identity_id):
        creds = _poll_until(
            lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
            lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
            timeout_s=_PROPAGATION_BUDGET_S,
            description=f"credentials to be vended for guest identity {identity_id}",
        )["Credentials"]
        return _client_from_credentials(ctx, "dynamodb", creds)

    session_a = _session_for(identity_a)
    session_b = _session_for(identity_b)

    # Each identity reads its own partition, asserted on the item bytes.
    items_a = _poll_until(
        lambda: _query(session_a, table, identity_a),
        lambda r: True,
        timeout_s=_PROPAGATION_BUDGET_S,
        description="identity A's session to be allowed its own partition",
    )
    assert len(items_a) == 1, (
        f"identity A must see exactly its own item; expected 1 row in partition {identity_a}, got "
        f"{len(items_a)}"
    )
    assert items_a[0]["blob"]["B"] == payloads[identity_a], (
        f"identity A read {items_a[0]['blob']['B']!r}, expected {payloads[identity_a]!r}"
    )

    items_b = _query(session_b, table, identity_b)
    assert len(items_b) == 1, (
        f"identity B must see exactly its own item; expected 1 row in partition {identity_b}, got "
        f"{len(items_b)}"
    )
    assert items_b[0]["blob"]["B"] == payloads[identity_b], (
        f"identity B read {items_b[0]['blob']['B']!r}, expected {payloads[identity_b]!r}"
    )

    # Every vended session is the pool role under Cognito's fixed session name.
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/CognitoIdentityCredentials"
    query_denied = _denial_message(session_arn, "dynamodb:Query", table_arn)
    cross_code, cross_message = _refusal(lambda: _query(session_a, table, identity_b))
    assert cross_code == _DENIED_CODE, (
        f"expected {_DENIED_CODE!r} for a cross-identity Query, got {cross_code!r}: "
        f"{cross_message!r}"
    )
    # The message names the denied action, which shows the condition was evaluated rather than
    # the statement being inert.
    assert cross_message == query_denied, (
        f"cross-identity Query refusal: expected {query_denied!r}, got {cross_message!r}"
    )

    # The mirror direction, so the scope is not simply a constant.
    reverse_code, reverse_message = _refusal(lambda: _query(session_b, table, identity_a))
    assert reverse_code == _DENIED_CODE, (
        f"expected {_DENIED_CODE!r} for the mirror cross-identity Query, got {reverse_code!r}: "
        f"{reverse_message!r}"
    )
    assert reverse_message == query_denied, (
        f"mirror cross-identity Query refusal: expected {query_denied!r}, got {reverse_message!r}"
    )

    # A second operation, so the scope is not Query-specific.
    own_item = _get_item(session_a, table, identity_a, item_id)["Item"]
    assert own_item["blob"]["B"] == payloads[identity_a], (
        f"identity A's GetItem returned {own_item['blob']['B']!r}, expected "
        f"{payloads[identity_a]!r}"
    )
    foreign_code, foreign_message = _refusal(
        lambda: _get_item(session_a, table, identity_b, item_id)
    )
    assert foreign_code == _DENIED_CODE, (
        f"expected {_DENIED_CODE!r} for a cross-identity GetItem, got {foreign_code!r}: "
        f"{foreign_message!r}"
    )
    get_denied = _denial_message(session_arn, "dynamodb:GetItem", table_arn)
    assert foreign_message == get_denied, (
        f"cross-identity GetItem refusal: expected {get_denied!r}, got {foreign_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
