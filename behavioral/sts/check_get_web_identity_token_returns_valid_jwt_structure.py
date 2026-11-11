"""get-web-identity-token-returns-valid-jwt-structure."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-returns-valid-jwt-structure"
GROUP = "data-plane"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "dp:endpoint", "plane:control", "plane:data", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetWebIdentityToken returns a 3-part RS256 JWT whose aud, exp, iss and sub claims match
    the request, response and account, signed by a key in the issuer's published JWKS."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    issuer = _ensure_outbound_federation_enabled(ctx, iam)

    audience = "https://sim2real.example.com/behavioral-check"
    caller = sts.get_caller_identity()
    resp = _get_web_identity_token_once_propagated(sts, audience)
    token = resp["WebIdentityToken"]
    expiration = resp["Expiration"]

    parts = token.split(".")
    assert len(parts) == 3, f"expected a 3-part JWT, got {len(parts)} parts"
    header_b64, payload_b64, sig_b64 = parts
    header = _b64url_json(header_b64)
    payload = _b64url_json(payload_b64)

    assert header.get("alg") == "RS256", header
    assert header.get("typ", "JWT") == "JWT", header

    kid = header.get("kid")
    assert kid, f"expected a kid in the token header, got {header}"
    jwks = _http_get_json(ctx, f"{issuer.rstrip('/')}/.well-known/jwks.json")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    assert jwk is not None, f"kid {kid} not present in issuer JWKS {jwks}"
    assert jwk.get("kty") == "RSA", f"expected an RSA JWK, got {jwk.get('kty')}"
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert _verify_rs256(signing_input, signature, jwk), (
        "WebIdentityToken RS256 signature must verify against the issuer's published JWKS key"
    )

    aud_claim = payload.get("aud")
    if isinstance(aud_claim, list):
        assert audience in aud_claim, aud_claim
    else:
        assert aud_claim == audience, aud_claim

    exp_claim = payload.get("exp")
    assert isinstance(exp_claim, (int, float)), payload
    exp_from_claim = datetime.fromtimestamp(exp_claim, tz=timezone.utc)
    assert abs((exp_from_claim - expiration).total_seconds()) <= 2, (
        exp_from_claim,
        expiration,
    )

    assert payload.get("iss") == issuer, (payload.get("iss"), issuer)

    sub_claim = payload.get("sub", "")
    assert isinstance(sub_claim, str) and caller["Account"] in sub_claim, (
        sub_claim,
        caller,
    )


def _b64url_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    data = base64.urlsafe_b64decode(padded.encode("ascii"))
    return json.loads(data)


def _http_get_json(ctx, url: str, timeout_s: float = 30) -> dict[str, Any]:
    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=timeout_s) as r:  # noqa: S310 - fixed https scheme
        return json.loads(r.read().decode())


def _b64url_to_int(segment: str) -> int:
    padded = segment + "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) signature against a JWK, in pure Python."""
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    decrypted = pow(int.from_bytes(signature, "big"), e, n)
    em = decrypted.to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    ps_len = k - len(prefix) - len(digest) - 3
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest
    return em == expected


def _get_web_identity_token_once_propagated(sts, audience: str, deadline_s: float = 30.0) -> dict:
    """Mint a token, retrying OutboundWebIdentityFederationDisabledException, which STS
    briefly returns after IAM enables federation; other errors propagate."""
    deadline = time.monotonic() + deadline_s
    delay = 0.5
    while True:
        try:
            return sts.get_web_identity_token(
                Audience=[audience], SigningAlgorithm="RS256", DurationSeconds=300
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "OutboundWebIdentityFederationDisabledException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 5.0)


def _ensure_outbound_federation_enabled(ctx, iam) -> str:
    try:
        info = iam.enable_outbound_web_identity_federation()
        issuer = info["IssuerIdentifier"]
        ctx.on_cleanup(lambda: _safe_disable_federation(iam))
    except ClientError as err:
        if err.response["Error"]["Code"] != "FeatureEnabled":
            raise
        issuer = iam.get_outbound_web_identity_federation_info()["IssuerIdentifier"]
    return issuer


def _safe_disable_federation(iam) -> None:
    try:
        iam.disable_outbound_web_identity_federation()
    except ClientError as err:
        if err.response["Error"]["Code"] != "FeatureDisabled":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
