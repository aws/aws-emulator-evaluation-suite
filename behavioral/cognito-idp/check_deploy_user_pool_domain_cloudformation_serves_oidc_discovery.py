"""deploy-user-pool-domain-cloudformation-serves-oidc-discovery."""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlsplit

from behavioral_harness import tags

CHECK = "deploy-user-pool-domain-cloudformation-serves-oidc-discovery"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed user pool domain is ACTIVE with a CloudFront distribution, issues a
    client_credentials access token over OAuth2, and that token's RS256 signature verifies against
    the pool's published JWKS."""
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")

    stack_name = ctx.unique_name("sim2real-cfn-dom-")
    domain = _sanitize_domain(stack_name)
    template = {
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": stack_name},
            },
            "Domain": {
                "Type": "AWS::Cognito::UserPoolDomain",
                "Properties": {"Domain": domain, "UserPoolId": {"Ref": "Pool"}},
            },
        },
        "Outputs": {"UserPoolId": {"Value": {"Ref": "Pool"}}},
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    pool_id = outputs["UserPoolId"]

    # Poll DescribeUserPoolDomain to ACTIVE: CloudFormation's UserPoolDomain resource
    # handler already waits for ACTIVE before marking CREATE_COMPLETE, so this should
    # resolve almost immediately — kept as a short safety net, not the primary wait.
    domain_desc = _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=domain).get("DomainDescription", {}),
        lambda desc: desc.get("Status") == "ACTIVE",
        timeout_s=15.0,
        interval_s=5.0,
    )
    assert domain_desc.get("Status") == "ACTIVE"
    # A real backing CloudFront distribution must have been allocated — not just a DB
    # record flipped to ACTIVE.
    assert domain_desc.get("CloudFrontDistribution"), (
        f"ACTIVE domain has no CloudFrontDistribution allocated: {domain_desc}"
    )

    resource_server_id = ctx.unique_name("sim2real-cfn-dom-rs-")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name=resource_server_id,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    scope = f"{resource_server_id}/read"
    m2m_client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cfn-dom-m2m-"),
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[scope],
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]
    client_id = m2m_client["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    client_secret = m2m_client["ClientSecret"]

    # The stack completes well before the CloudFront distribution behind the domain answers
    # HTTPS, so most of the time budget goes to polling for a successful token response.
    access_token = _get_client_credentials_token(ctx, domain, client_id, client_secret, scope, timeout_s=700.0)

    header_b64, payload_b64, sig_b64 = access_token.split(".")
    header = _decode_jwt_segment(header_b64)
    assert header.get("alg") == "RS256", f"expected alg RS256, got {header.get('alg')}"
    kid = header.get("kid")
    assert kid, f"expected a kid in the token header, got {header}"

    payload = _decode_jwt_segment(payload_b64)
    # The issuer is https://cognito-idp.<region>.<domain>/<user pool id>; the domain is the
    # target's own, so the service label, region and pool id are matched by position.
    iss = payload.get("iss")
    iss_parts = urlsplit(iss) if isinstance(iss, str) else None
    iss_labels = (iss_parts.hostname or "").split(".") if iss_parts else []
    assert (iss_parts is not None and iss_parts.scheme == "https"
            and iss_labels[:2] == ["cognito-idp", ctx.region] and len(iss_labels) > 2
            and all(iss_labels[2:]) and iss_parts.path == f"/{pool_id}"
            and not iss_parts.query and not iss_parts.fragment), (
        f"the token issued through the deployed domain must be issued by "
        f"https://cognito-idp.{ctx.region}.<domain>/{pool_id}, got iss={iss!r}"
    )

    jwks_url = f"{iss}/.well-known/jwks.json"
    jwks, jwks_err = _poll_http_json(ctx, jwks_url, timeout_s=15.0, interval_s=5.0)
    assert jwks is not None, f"JWKS endpoint never became reachable (last error: {jwks_err!r})"
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    assert jwk is not None, f"kid {kid} not present in the pool's published JWKS {jwks}"

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert _verify_rs256(signing_input, signature, jwk), (
        "AccessToken issued through the CloudFormation-deployed domain must RS256-verify "
        "against the pool's published JWKS key"
    )


def _sanitize_domain(name: str) -> str:
    domain = name.lower().replace("_", "-").strip("-")
    if not domain[0].isalpha():
        domain = "d" + domain
    return domain[:63].rstrip("-")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _poll_http_json(ctx, url: str, *, timeout_s: float, interval_s: float) -> tuple[dict[str, Any] | None, BaseException | None]:
    target, route_headers = ctx.endpoint_route(url)
    deadline = time.monotonic() + timeout_s
    last_err: BaseException | None = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(target, headers=route_headers)
        try:
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8")), None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as exc:
            last_err = exc
        time.sleep(interval_s)
    return None, last_err


def _get_client_credentials_token(
    ctx, domain: str, client_id: str, client_secret: str, scope: str, *, timeout_s: float
) -> str:
    """Poll the deployed domain's own /oauth2/token until it serves a real token — its
    readiness to complete an OAuth2 flow IS the observable proof that the CloudFormation-
    deployed domain (and the CloudFront distribution behind it) is actually live."""
    base_url, route_headers = f"https://{domain}.auth.{ctx.region}.amazoncognito.com", {}
    token_url = f"{base_url}/oauth2/token"
    body = urlencode({"grant_type": "client_credentials", "scope": scope}).encode()
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    deadline = time.monotonic() + timeout_s
    last_err: BaseException | None = None
    server_errors = 0
    while time.monotonic() < deadline:
        req = urllib.request.Request(token_url, data=body, method="POST", headers=route_headers)  # customer-built AWS host
        req.add_header("Authorization", f"Basic {basic}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
                return json.loads(resp.read().decode("utf-8"))["access_token"]
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code != 404:
                raise AssertionError(f"token endpoint rejected request: {exc.code} {exc.read()}") from exc
            if exc.code >= 500:
                server_errors += 1
                if server_errors >= 10:
                    raise AssertionError(f"token endpoint answered {exc.code} {server_errors} times: {exc.read()}") from exc
            last_err = exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_err = exc
        time.sleep(5.0)
    raise AssertionError(f"token endpoint for domain {domain} never became reachable: {last_err!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) JWT signature against a JWK public
    key, pure-Python (no external crypto dependency)."""
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    decrypted = pow(int.from_bytes(signature, "big"), e, n)
    em = decrypted.to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    # DigestInfo DER prefix for SHA-256.
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    ps_len = k - len(prefix) - len(digest) - 3
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest
    return em == expected


def _delete_stack(cfn: Any, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
