"""developer-authenticated-credentials-write-and-read-dynamodb."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "developer-authenticated-credentials-write-and-read-dynamodb"
GROUP = 'vended-credentials'
SERVICES = ['cognito-identity']

# GetCredentialsForIdentity returns the secret under the key `SecretKey`, not `SecretAccessKey`,
# and the vended session's principal is always named `CognitoIdentityCredentials`.
SESSION_NAME = "CognitoIdentityCredentials"
# The Logins key for a token minted by GetOpenIdTokenForDeveloperIdentity is the Cognito Identity
# provider itself, never the developer provider name.
DEVELOPER_TOKEN_LOGIN = "cognito-identity.amazonaws.com"
# A brand-new role's first vended session is briefly rejected by the callee while the trust policy
# and the inline grant propagate.
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
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


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _set_roles(ci, pool_id, roles, role_mappings=None, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    kwargs = {"IdentityPoolId": pool_id, "Roles": roles}
    if role_mappings is not None:
        kwargs["RoleMappings"] = role_mappings
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """A client signed with the vended credentials, passed by value rather than via os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _denial(fn):
    """Call fn() and return (Code, Message) of its refusal; an accepted call raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Credentials vended for a developer-authenticated identity PutItem and GetItem a DynamoDB row
    their role grants with the bytes intact, and an ungranted Scan from the same session is refused.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    ddb = ctx.client("dynamodb")

    table = ctx.unique_name("sim2real-behav-cidp-tbl-")
    ddb.create_table(
        TableName=table,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]

    developer_provider = ctx.unique_name("sim2real-behav-devauth-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_devauth_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # The trust policy needs the pool id, so the role is created after the pool. The developer
    # token's amr includes 'authenticated', so a trust policy keyed on it admits the identity.
    auth_role_name = ctx.unique_name("sim2real-behav-devauth-role-")[:64]
    auth_role_arn = iam.create_role(
        RoleName=auth_role_name,
        AssumeRolePolicyDocument=_cognito_trust_policy(pool_id, amr=["authenticated"]),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=auth_role_name))
    policy_name = "sim2real-behav-devauth-grant"
    iam.put_role_policy(
        RoleName=auth_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                "Resource": table_arn,
            }],
        }),
    )
    # Registered after delete_role so LIFO cleanup drops the inline policy first.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=auth_role_name,
                                                  PolicyName=policy_name))
    _set_roles(ci, pool_id, {"authenticated": auth_role_arn})

    developer_user_id = ctx.unique_name("sim2real-behav-devuser-")
    token_resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: developer_user_id}
    )
    token_identity_id = token_resp["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[token_identity_id]))

    vended = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=token_identity_id,
            Logins={DEVELOPER_TOKEN_LOGIN: token_resp["Token"]},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=120.0,
        description="GetCredentialsForIdentity to vend credentials for the developer identity",
    )
    creds = vended["Credentials"]
    creds_identity_id = vended["IdentityId"]

    assert set(creds) >= {"AccessKeyId", "SecretKey", "SessionToken"}, (
        f"incomplete credentials: {sorted(creds)!r}"
    )
    assert creds_identity_id == token_identity_id, (
        f"identity id changed between GetOpenIdTokenForDeveloperIdentity "
        f"({token_identity_id!r}) and GetCredentialsForIdentity ({creds_identity_id!r})"
    )

    vended_arn = _poll_until(
        lambda: _client_from_credentials(ctx, "sts", creds).get_caller_identity(),
        lambda r: bool(r.get("Arn")),
        timeout_s=120.0,
        description="the vended session to become usable by STS",
    )["Arn"]
    assert vended_arn.split("/")[1] == auth_role_name, (
        f"vended identity was {vended_arn!r}, expected a session of the authenticated role "
        f"{auth_role_name!r}"
    )
    assert vended_arn.endswith(f"/{SESSION_NAME}"), (
        f"a Cognito-vended session is always named {SESSION_NAME!r}, got {vended_arn!r}"
    )

    # PutItem/GetItem sit inside the session policy Cognito injects, so the role grant suffices.
    ddb_vended = _client_from_credentials(ctx, "dynamodb", creds)
    blob = uuid.uuid4().bytes
    row_key = f"sim2real-{uuid.uuid4().hex[:12]}"
    _poll_until(
        lambda: ddb_vended.put_item(
            TableName=table, Item={"pk": {"S": row_key}, "blob": {"B": blob}}
        ),
        lambda r: r.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200,
        timeout_s=180.0,
        interval_s=5.0,
        description="the granted PutItem to be accepted for the vended session",
    )
    item = ddb_vended.get_item(
        TableName=table, Key={"pk": {"S": row_key}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"GetItem with the vended credentials found no row at pk={row_key!r} after PutItem "
        f"reported success"
    )
    assert item["blob"]["B"] == blob, (
        f"GetItem returned {item!r}, wrote {blob!r}"
    )

    # The role grants only PutItem and GetItem, so Scan under the vended credentials is refused,
    # naming the vended session principal, the action and the table.
    denied = _denial(lambda: ddb_vended.scan(TableName=table, Limit=1))
    expected = (
        "AccessDeniedException",
        f"User: {vended_arn} is not authorized to perform: dynamodb:Scan on resource: {table_arn}"
        " because no identity-based policy allows the dynamodb:Scan action",
    )
    assert denied == expected, f"expected {expected!r} for an ungranted Scan, got {denied!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
