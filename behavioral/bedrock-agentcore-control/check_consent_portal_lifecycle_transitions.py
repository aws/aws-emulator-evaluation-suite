"""consent-portal-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "consent-portal-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConsentPortal create->update->delete workflow state machine transitions correctly."""
    client = ctx.client("bedrock-agentcore-control")
    cognito = ctx.client("cognito-idp")
    region = client.meta.region_name
    exec_role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3cpx")
    gw_role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3cpg")

    pool_name = _alnum_name(ctx, "sim2realCpPool")
    pool = cognito.create_user_pool(PoolName=pool_name, UserPoolTags={"sim2real": CHECK})
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(cognito.delete_user_pool, UserPoolId=pool_id))
    pool_client = cognito.create_user_pool_client(UserPoolId=pool_id, ClientName=_alnum_name(ctx, "sim2realCpClient"))
    client_id = pool_client["UserPoolClient"]["ClientId"]
    discovery_url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}/.well-known/openid-configuration"

    oauth_name = _alnum_name(ctx, "sim2reals3cpo")
    oauth = client.create_oauth2_credential_provider(
        name=oauth_name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "oauthDiscovery": {"discoveryUrl": discovery_url},
                "clientId": client_id,
                "clientSecret": "sim2real-consent-portal-client-secret",
            }
        },
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client.delete_oauth2_credential_provider, name=oauth_name))
    oauth_arn = oauth["credentialProviderArn"]

    gw_name = _gateway_name(ctx, "sim2realcpgw")
    gateway = client.create_gateway(
        name=gw_name,
        roleArn=gw_role_arn,
        authorizerType="CUSTOM_JWT",
        authorizerConfiguration={
            "customJWTAuthorizer": {
                "discoveryUrl": discovery_url,
                "allowedClients": [client_id],
            }
        },
        tags={"sim2real": CHECK},
    )
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))
    _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )

    portal_name = ctx.unique_name("sim2real-cportal-")[:50]
    created = _retry_role_propagation(
        lambda: client.create_consent_portal(
            executionRoleArn=exec_role_arn,
            idpConfig={"credentialProviderArn": oauth_arn, "scopes": ["openid"]},
            name=portal_name,
            sources=[{"identifier": gateway_id, "type": "agentcore-gateway"}],
            description="initial consent portal",
            tags={"sim2real": CHECK},
        )
    )
    portal_id = created["consentPortalId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: client.get_consent_portal(consentPortalIdentifier=portal_id)["status"],
            lambda: client.delete_consent_portal(consentPortalIdentifier=portal_id),
            what=f"consent portal {portal_id}",
        )
    )

    active = _poll_until(
        lambda: client.get_consent_portal(consentPortalIdentifier=portal_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=180.0,
    )
    assert active["name"] == portal_name, f"expected name {portal_name!r}, got {active['name']!r}"

    client.update_consent_portal(consentPortalIdentifier=portal_id, description="updated consent portal")
    updated = _poll_until(
        lambda: client.get_consent_portal(consentPortalIdentifier=portal_id),
        lambda r: r["status"] == "ACTIVE" and r.get("description") == "updated consent portal",
        timeout_s=180.0,
    )
    assert updated["description"] == "updated consent portal", (
        f"expected description 'updated consent portal', got {updated['description']!r}"
    )

    client.delete_consent_portal(consentPortalIdentifier=portal_id)

    final_code, final_message = _error_detail(
        lambda: client.get_consent_portal(consentPortalIdentifier=portal_id), wait_s=180.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {final_code!r}"
    )
    expected_message = f"No consent portal found for id {portal_id}"
    assert final_message == expected_message, (
        f"expected message {expected_message!r}, got {final_message!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_gateway(control, gateway_id):
    """Delete every target first (DeleteGateway is refused while one exists), then the gateway."""
    try:
        pages = control.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gateway_id)
        target_ids = [t["targetId"] for page in pages for t in page.get("items", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for target_id in target_ids:
        _ac_delete_and_wait(
            lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch in "-_")


def _gateway_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _create_role(ctx, principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _error_detail(fn, *, wait_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn raises. While fn still succeeds it is
    retried until wait_s elapses; a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        time.sleep(interval_s)


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assum" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _delete_ignore_not_found(delete_fn, **kwargs) -> None:
    from botocore.exceptions import ClientError

    try:
        delete_fn(**kwargs)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
