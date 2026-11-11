"""xsvc-cognito-idp-2-avp-group-removal-applies-only-to-reissued-token."""
from __future__ import annotations

import base64
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-2-avp-group-removal-applies-only-to-reissued-token"
GROUP = "cognito-token-authorization"
SERVICES = ["cognito-idp", "verifiedpermissions"]

_PRINCIPAL_TYPE = "App::User"
_GROUP_TYPE = "App::UserGroup"
_ACTION = {"actionType": "App::Action", "actionId": "read"}
_RESOURCE = {"entityType": "App::Doc", "entityId": "doc-1"}
_ADMINS = "admins"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """AVP decides from the token's claims, not live pool state: after AdminRemoveUserFromGroup the
    token issued while in `admins` is still ALLOWed, and a freshly issued token without
    `cognito:groups` is DENYed as the same `<poolId>|<sub>` principal.
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

    idp.admin_remove_user_from_group(UserPoolId=pool_id, Username="alice", GroupName=_ADMINS)
    groups = idp.admin_list_groups_for_user(UserPoolId=pool_id, Username="alice")["Groups"]
    assert groups == [], f"alice still listed in groups {[g['GroupName'] for g in groups]!r}"

    stale = _authorize(avp, store_id, identityToken=alice["IdToken"])
    assert stale["decision"] == "ALLOW", (
        f"the token minted while alice was in admins should still ALLOW (claims are fixed at "
        f"issue), got {stale!r}"
    )

    reissued = _authenticate(idp, pool_id, client_id, "alice", password)
    assert "cognito:groups" not in _claims(reissued["IdToken"]), (
        f"reissued token still claims {_claims(reissued['IdToken']).get('cognito:groups')!r}"
    )
    fresh = _authorize(avp, store_id, identityToken=reissued["IdToken"])
    assert fresh["decision"] == "DENY", f"the reissued, group-less token got {fresh!r}"
    assert fresh["principal"] == alice_principal, (
        f"the reissued token mapped to {fresh['principal']!r}, expected the same {alice_principal!r}"
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



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
