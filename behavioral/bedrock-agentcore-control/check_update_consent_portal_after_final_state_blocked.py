"""update-consent-portal-after-final-state-blocked."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-consent-portal-after-final-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConsentPortal against a portal that has already been fully
    deleted is rejected with ResourceNotFoundException, never silently
    accepted; a still-live portal can still be updated (positive control)."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)
    discovery_url = _cognito_discovery_url(ctx)

    gw_name = _kebab(ctx, "sim2realgw", 48)
    gw = _retry_role_propagation(
        lambda: bac.create_gateway(
            name=gw_name,
            roleArn=role_arn,
            authorizerType="CUSTOM_JWT",
            authorizerConfiguration={
                "customJWTAuthorizer": {
                    "discoveryUrl": discovery_url,
                    "allowedAudience": ["sim2real-test-audience"],
                }
            },
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(lambda: bac.get_gateway(gatewayIdentifier=gateway_id), lambda r: r["status"] == "READY")

    provider_name = _alnum(ctx, "sim2realOauth", 128)
    provider = bac.create_oauth2_credential_provider(
        name=provider_name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "clientId": "sim2real-test-client-id",
                "clientSecret": "sim2real-test-client-secret",
                "oauthDiscovery": {"discoveryUrl": discovery_url},
            }
        },
    )
    credential_provider_arn = provider["credentialProviderArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bac.delete_oauth2_credential_provider(name=provider_name))
    )

    def _create_portal(name: str) -> str:
        resp = _retry_role_propagation(
            lambda: bac.create_consent_portal(
                executionRoleArn=role_arn,
                idpConfig={"credentialProviderArn": credential_provider_arn, "scopes": ["openid"]},
                name=name,
                sources=[{"identifier": gateway_id, "type": "agentcore-gateway"}],
            )
        )
        return resp["consentPortalId"]

    portal_name = _kebab(ctx, "sim2realcp", 50)
    portal_id = _create_portal(portal_name)
    ctx.on_cleanup(lambda: _ac_delete_consent_portal(bac, portal_id))
    _poll_until(
        lambda: bac.get_consent_portal(consentPortalIdentifier=portal_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )

    bac.delete_consent_portal(consentPortalIdentifier=portal_id)
    _poll_until_gone(bac, portal_id, timeout_s=180.0)

    code, message = _error(
        lambda: bac.update_consent_portal(
            consentPortalIdentifier=portal_id, description="should not apply"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No consent portal found for id {portal_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a live portal can still be updated.
    portal2_name = _kebab(ctx, "sim2realcp2", 50)
    portal_id2 = _create_portal(portal2_name)
    ctx.on_cleanup(lambda: _ac_delete_consent_portal(bac, portal_id2))
    _poll_until(
        lambda: bac.get_consent_portal(consentPortalIdentifier=portal_id2),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )
    updated = bac.update_consent_portal(consentPortalIdentifier=portal_id2, description="updated")
    assert updated["consentPortalId"] == portal_id2


def _cognito_discovery_url(ctx) -> str:
    """The OIDC discovery URL of a Cognito user pool this check creates: its pool id under
    the endpoint that serves it.

    The check owns the issuer, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-ac-issuer-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}/.well-known/openid-configuration"


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


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9]", "", raw)
    return name[:maxlen]


def _kebab(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9-]", "-", raw).strip("-")
    return name[:maxlen]


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
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


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    """IAM role trust is not immediately assumable after create_role; retry
    only the specific ValidationException that names the propagation delay."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assum" in message.lower():
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _ac_delete_consent_portal(bac, portal_id):
    # The portal names the gateway as a source, so it must be gone before the gateway delete.
    _ac_delete_and_wait(
        lambda: bac.get_consent_portal(consentPortalIdentifier=portal_id)["status"],
        lambda: bac.delete_consent_portal(consentPortalIdentifier=portal_id),
        what=f"consent portal {portal_id}",
    )


def _poll_until_gone(bac, portal_id: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bac.get_consent_portal(consentPortalIdentifier=portal_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"consent portal {portal_id} was not fully removed within {timeout_s}s")


def _create_agentcore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _kebab(ctx, "sim2real-bac-role", 64)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
