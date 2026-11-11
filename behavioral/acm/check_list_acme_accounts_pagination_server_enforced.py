"""list-acme-accounts-pagination-server-enforced."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "list-acme-accounts-pagination-server-enforced"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A ListAcmeAccounts NextToken is stable (repeating it returns the same page, and the pages
    cover both accounts), and a forged token is rejected with ValidationException."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)
    eab_arn = _create_eab(ctx, acm, endpoint_arn, role_arn)
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"][
        "EndpointUrl"
    ]

    account_url_1 = _register_acme_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])
    account_url_2 = _register_acme_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])
    assert account_url_1 != account_url_2

    page1 = acm.list_acme_accounts(AcmeEndpointArn=endpoint_arn, MaxResults=1)
    assert len(page1["AcmeAccounts"]) == 1
    token = page1.get("NextToken")
    assert token, "expected a NextToken with two accounts registered and MaxResults=1"

    # Repeating the same token twice must yield the identical page (server-issued,
    # stable cursor), not a moving/inconsistent view.
    repeat_a = acm.list_acme_accounts(AcmeEndpointArn=endpoint_arn, MaxResults=1, NextToken=token)
    repeat_b = acm.list_acme_accounts(AcmeEndpointArn=endpoint_arn, MaxResults=1, NextToken=token)
    assert repeat_a["AcmeAccounts"] == repeat_b["AcmeAccounts"]
    assert repeat_a.get("NextToken") == repeat_b.get("NextToken")

    seen_urls = {
        page1["AcmeAccounts"][0]["AccountUrl"],
        repeat_a["AcmeAccounts"][0]["AccountUrl"],
    }
    assert seen_urls == {account_url_1, account_url_2}, (
        f"pagination missed or duplicated accounts across pages: {seen_urls}"
    )

    # A forged token cannot be used to skip/replay arbitrary pages.
    code, message = _error(
        lambda: acm.list_acme_accounts(
            AcmeEndpointArn=endpoint_arn, MaxResults=1, NextToken="forged-not-a-real-token"
        )
    )
    assert code == "ValidationException"
    expected_message = (
        "Pagination token exception in operation 'ListAcmeAccounts': "
        "invalid payload wrapping schema 32394"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_endpoint_active(acm, arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError("ACME endpoint creation failed")
        time.sleep(interval_s)
    raise AssertionError("ACME endpoint never became ACTIVE within timeout")


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_endpoint_active(acm, arn)
    return arn


def _create_eab_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-acme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _create_eab(ctx, acm, endpoint_arn, role_arn):
    """CreateAcmeExternalAccountBinding PassRole-checks role_arn, and IAM role visibility
    at that check lags IAM's own GetRole propagation by several seconds — retry the
    transient AccessDeniedException rather than treat it as a real rejection."""
    last_err = None
    for _ in range(12):
        try:
            arn = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda a=arn: acm.delete_acme_external_account_binding(
                    AcmeExternalAccountBindingArn=a
                )
            )
            return arn
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode_any(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


def _http(ctx, url, data=None, headers=None, method=None):
    req = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def _register_acme_account(ctx, directory_url, key_id, mac_key):
    """Register an ACME account with an EAB over raw RFC 8555 HTTP/JWS, using only 'cryptography'."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    status, _, body = _http(ctx, directory_url)
    if status != 200:
        raise AssertionError(f"ACME directory fetch failed: {status} {body!r}")
    directory = json.loads(body)

    status, headers, _ = _http(ctx, directory["newNonce"], method="HEAD")
    nonce = headers.get("replay-nonce")
    if not nonce:
        status, headers, _ = _http(ctx, directory["newNonce"], method="GET")
        nonce = headers.get("replay-nonce")
    if not nonce:
        raise AssertionError("ACME server did not return a Replay-Nonce")

    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    new_account_url = directory["newAccount"]

    mac_key_bytes = _b64decode_any(mac_key)
    eab_protected = _b64url(
        json.dumps({"alg": "HS256", "kid": key_id, "url": new_account_url}).encode()
    )
    eab_payload = _b64url(json.dumps(jwk).encode())
    eab_sig = _b64url(
        hmac.new(mac_key_bytes, f"{eab_protected}.{eab_payload}".encode(), hashlib.sha256).digest()
    )
    eab_jws = {"protected": eab_protected, "payload": eab_payload, "signature": eab_sig}

    outer_protected = _b64url(
        json.dumps({"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": new_account_url}).encode()
    )
    outer_payload = _b64url(
        json.dumps({"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}).encode()
    )
    signing_input = f"{outer_protected}.{outer_payload}".encode()
    der_sig = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    outer_sig = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    body_obj = json.dumps(
        {"protected": outer_protected, "payload": outer_payload, "signature": outer_sig}
    ).encode()
    status, headers, resp_body = _http(ctx,
        new_account_url, data=body_obj, headers={"Content-Type": "application/jose+json"}, method="POST"
    )
    if status not in (200, 201):
        raise AssertionError(f"ACME newAccount failed: {status} {resp_body!r}")
    account_url = headers.get("location")
    if not account_url:
        raise AssertionError("ACME newAccount response missing Location header")
    return account_url


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
