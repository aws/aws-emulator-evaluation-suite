"""xsvc-cognito-idp-2-avp-token-from-foreign-pool-rejected."""
from __future__ import annotations

import base64
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-2-avp-token-from-foreign-pool-rejected"
GROUP = "cognito-token-authorization"
SERVICES = ["cognito-idp", "verifiedpermissions"]

_PRINCIPAL_TYPE = "App::User"
_GROUP_TYPE = "App::UserGroup"
_ACTION = {"actionType": "App::Action", "actionId": "read"}
_RESOURCE = {"entityType": "App::Doc", "entityId": "doc-1"}
_ADMINS = "admins"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A valid token from a second Cognito pool (same username, same `admins` group) is refused with
    ResourceNotFoundException by a policy store whose identity source names only the first pool,
    while the first pool's admins token is ALLOWed before and after.
    """
    idp = ctx.client("cognito-idp")
    avp = ctx.client("verifiedpermissions")
    password = _password()

    pool_id, pool_arn = _make_pool(ctx, idp, "sim2real-xsvc-avp-pool-")
    client_id = _make_client(ctx, idp, pool_id, "sim2real-xsvc-avp-client-")
    _make_group(ctx, idp, pool_id, _ADMINS)
    alice_sub = _make_user(ctx, idp, pool_id, "alice", password)
    _add_to_group(ctx, idp, pool_id, "alice", _ADMINS)

    store_id = _make_store(ctx, avp)
    _make_identity_source(ctx, avp, store_id, pool_arn, [client_id])
    _make_group_policy(ctx, avp, store_id, pool_id, _ADMINS)

    alice = _authenticate(idp, pool_id, client_id, "alice", password)
    alice_principal = {"entityType": _PRINCIPAL_TYPE, "entityId": f"{pool_id}|{alice_sub}"}

    # Positive control: the genuine admins-group token is ALLOWed on this wiring.
    allow = _poll_decision(avp, store_id, "ALLOW", identityToken=alice["IdToken"])
    assert allow["decision"] == "ALLOW", f"positive control: alice (admins) got {allow!r}"
    assert allow["principal"] == alice_principal, (
        f"positive control principal {allow['principal']!r}, expected {alice_principal!r}"
    )

    # The unrelated pool mirrors the first one's names exactly, so only the issuer differs.
    other_pool_id, _ = _make_pool(ctx, idp, "sim2real-xsvc-avp-foreign-pool-")
    other_client_id = _make_client(ctx, idp, other_pool_id, "sim2real-xsvc-avp-foreign-client-")
    _make_group(ctx, idp, other_pool_id, _ADMINS)
    _make_user(ctx, idp, other_pool_id, "alice", password)
    _add_to_group(ctx, idp, other_pool_id, "alice", _ADMINS)
    foreign = _authenticate(idp, other_pool_id, other_client_id, "alice", password)

    foreign_claims = _claims(foreign["IdToken"])
    assert foreign_claims.get("cognito:groups") == [_ADMINS], f"foreign claims {foreign_claims!r}"
    assert foreign_claims["iss"].endswith("/" + other_pool_id), (
        f"foreign token iss {foreign_claims['iss']!r} does not name {other_pool_id!r}"
    )
    assert foreign_claims["iss"] != _claims(alice["IdToken"])["iss"], "both pools share an issuer"
    me = idp.get_user(AccessToken=foreign["AccessToken"])
    assert me["Username"] == "alice", f"Cognito rejected its own foreign-pool token: {me!r}"

    no_source = (f"Identity Source does not exist for issuer {foreign_claims['iss']} "
                 f"in policy store {store_id}")
    code = _refusal(lambda: avp.is_authorized_with_token(
        policyStoreId=store_id, identityToken=foreign["IdToken"], action=_ACTION, resource=_RESOURCE))
    assert code == ("ResourceNotFoundException", no_source), (
        f"an ID token from a pool with no identity source should be ResourceNotFoundException, got {code!r}"
    )
    code = _refusal(lambda: avp.is_authorized_with_token(
        policyStoreId=store_id, accessToken=foreign["AccessToken"], action=_ACTION, resource=_RESOURCE))
    assert code == ("ResourceNotFoundException", no_source), (
        f"an access token from a pool with no identity source should be ResourceNotFoundException, got {code!r}"
    )

    # Wiring intact: the policy store still exists and still ALLOWs its own pool's token,
    # so the ResourceNotFoundException above was about the issuer, not the store.
    again = _authorize(avp, store_id, identityToken=alice["IdToken"])
    assert again["decision"] == "ALLOW" and again["principal"] == alice_principal, (
        f"after the foreign-pool rejection the home token got {again!r}"
    )


def _password() -> str:
    # Satisfies the default Cognito password policy (upper, lower, digit, symbol, >= 8).
    return "Aa1!" + secrets.token_urlsafe(18)


def _make_pool(ctx, idp, prefix):
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name(prefix),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id, pool["Arn"]


def _make_client(ctx, idp, pool_id, prefix):
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name(prefix),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _make_group(ctx, idp, pool_id, name):
    idp.create_group(UserPoolId=pool_id, GroupName=name)
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=name))


def _make_user(ctx, idp, pool_id, username, password):
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    attrs = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    subs = [a["Value"] for a in attrs if a["Name"] == "sub"]
    assert len(subs) == 1, f"AdminGetUser for {username!r} returned sub attributes {subs!r}"
    return subs[0]


def _add_to_group(ctx, idp, pool_id, username, group):
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    ctx.on_cleanup(lambda: idp.admin_remove_user_from_group(
        UserPoolId=pool_id, Username=username, GroupName=group))


def _authenticate(idp, pool_id, client_id, username, password):
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = resp.get("AuthenticationResult")
    assert result and result.get("IdToken") and result.get("AccessToken"), (
        f"AdminInitiateAuth for {username!r} returned no tokens: "
        f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'}!r}"
    )
    return result


def _claims(jwt):
    parts = jwt.split(".")
    assert len(parts) == 3, f"token is not a three-part JWT: {len(parts)} parts"
    body = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(body))


def _retry_not_found(fn, timeout_s=60.0, interval_s=2.0):
    """A just-created policy store is briefly invisible to its own sub-resource calls
    (CreateIdentitySource -> ResourceNotFoundException 'Policy Store does not exist' for
    ~2 s). Retry only that code, bounded."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.time() > deadline:
                raise
            time.sleep(interval_s)


def _make_store(ctx, avp):
    store_id = avp.create_policy_store(
        validationSettings={"mode": "OFF"},
        description=ctx.unique_name("sim2real-xsvc-avp-store-"),
        deletionProtection="DISABLED",
        tags={"sim2real": CHECK},
    )["policyStoreId"]
    ctx.on_cleanup(lambda: avp.delete_policy_store(policyStoreId=store_id))
    return store_id


def _make_identity_source(ctx, avp, store_id, pool_arn, client_ids):
    source_id = _retry_not_found(lambda: avp.create_identity_source(
        policyStoreId=store_id,
        principalEntityType=_PRINCIPAL_TYPE,
        configuration={"cognitoUserPoolConfiguration": {
            "userPoolArn": pool_arn,
            "clientIds": list(client_ids),
            "groupConfiguration": {"groupEntityType": _GROUP_TYPE},
        }},
    ))["identitySourceId"]
    ctx.on_cleanup(lambda: avp.delete_identity_source(
        policyStoreId=store_id, identitySourceId=source_id))
    return source_id


def _make_group_policy(ctx, avp, store_id, pool_id, group):
    statement = (
        f'permit(principal in {_GROUP_TYPE}::"{pool_id}|{group}", '
        f'action == {_ACTION["actionType"]}::"{_ACTION["actionId"]}", resource);'
    )
    policy_id = _retry_not_found(lambda: avp.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}},
    ))["policyId"]
    ctx.on_cleanup(lambda: avp.delete_policy(policyStoreId=store_id, policyId=policy_id))
    return policy_id


def _authorize(avp, store_id, **token):
    return _retry_not_found(lambda: avp.is_authorized_with_token(
        policyStoreId=store_id, action=_ACTION, resource=_RESOURCE, **token))


def _poll_decision(avp, store_id, want, timeout_s=60.0, interval_s=2.0, **token):
    """Poll until the decision is `want`: a just-written policy or identity-source update
    is eventually consistent. Returns the last response either way; the caller asserts."""
    deadline = time.time() + timeout_s
    while True:
        resp = _authorize(avp, store_id, **token)
        if resp["decision"] == want or time.time() > deadline:
            return resp
        time.sleep(interval_s)


def _refusal(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so
    an accepted token is never reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        "real AWS rejects this token, but IsAuthorizedWithToken SUCCEEDED and returned "
        f"{ {k: v for k, v in result.items() if k != 'ResponseMetadata'}!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
