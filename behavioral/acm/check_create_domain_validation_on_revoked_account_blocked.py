"""create-domain-validation-on-revoked-account-blocked."""
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


CHECK = "create-domain-validation-on-revoked-account-blocked"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After RevokeAcmeAccount, the account's RFC 8555 account update that succeeded before is
    rejected as urn:ietf:params:acme:error:unauthorized and changes no contacts, while a second,
    still-valid account on the same endpoint can still update itself."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)
    eab_arn = _create_binding_with_retry(acm, endpoint_arn, role_arn)[
        "ExternalAccountBinding"
    ]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"][
        "EndpointUrl"
    ]
    directory = _acme_directory(ctx, endpoint_url)

    acct_a = _register_acme_account(ctx, directory, creds["KeyId"], creds["MacKey"])
    acct_b = _register_acme_account(ctx, directory, creds["KeyId"], creds["MacKey"])
    assert acct_a["account_url"] != acct_b["account_url"], (
        f"expected two distinct ACME account URLs, got {acct_a['account_url']!r} for both"
    )

    allowed_contact = "mailto:sim2real-before-revoke@example.com"
    status, body = _settle_account_writable(ctx, acct_a, allowed_contact)
    assert status == 200, (
        f"expected the pre-revocation account update to succeed, got HTTP {status}: {body!r}"
    )
    assert allowed_contact in _described_contacts(acm, endpoint_arn, acct_a["account_url"]), (
        "pre-revocation contact update did not persist, so the check cannot attribute the "
        "post-revocation rejection to revocation"
    )

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=acct_a["account_url"])
    status_a = acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=acct_a["account_url"]
    )["AcmeAccount"]["Status"]
    assert status_a == "REVOKED", f"expected account A status REVOKED, got {status_a!r}"

    blocked_contact = "mailto:sim2real-should-be-blocked@example.com"
    status, body = _acme_update_contact(ctx, acct_a, blocked_contact)
    assert status >= 400, (
        f"the revoked account's ACME-protocol account update was ACCEPTED (HTTP {status}): {body!r}"
    )
    problem = _acme_problem_type(body)
    assert problem == "urn:ietf:params:acme:error:unauthorized", (
        f"expected the RFC 8555 standard 'unauthorized' problem type, got {problem!r} "
        f"(HTTP {status}, body {body!r})"
    )
    # A role-assumption propagation failure is also `unauthorized` at HTTP 403, so the problem
    # type alone cannot attribute this rejection to the revocation.
    assert _ROLE_ASSUME_FAILURE not in body, (
        f"the post-revocation rejection is the acm-acme role-assumption failure, not the "
        f"revocation: {body!r}"
    )

    contacts_after = _described_contacts(acm, endpoint_arn, acct_a["account_url"])
    assert blocked_contact not in contacts_after, (
        f"revoked account's contact info changed despite the protocol rejection: {contacts_after!r}"
    )
    assert allowed_contact in contacts_after, (
        f"revoked account lost the contact its pre-revocation update set: {contacts_after!r}"
    )

    control_contact = "mailto:sim2real-control@example.com"
    status_b, body_b = _settle_account_writable(ctx, acct_b, control_contact)
    assert status_b == 200, (
        f"still-valid control account's update failed with HTTP {status_b}: {body_b!r}"
    )
    assert control_contact in _described_contacts(acm, endpoint_arn, acct_b["account_url"]), (
        "still-valid control account's contact update did not persist"
    )


def _create_binding_with_retry(acm, endpoint_arn, role_arn, timeout_s=180.0, interval_s=3.0):
    """Create the binding, retrying only the iam:PassRole AccessDenied IAM returns for a role it
    has not yet propagated; a real entitlement gap still fails at the deadline."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s of IAM "
        f"propagation retries: {last_exc}"
    )


_ROLE_ASSUME_FAILURE = b"Unable to assume role"


def _settle_account_writable(ctx, account: dict, contact: str, timeout_s=240.0, interval_s=5.0):
    """Account update retrying only the 403 "Unable to assume role" acm-acme returns until it can
    assume the role (being allowed to pass it propagates separately). Only pre-revocation writes
    use it: that 403 shares the `unauthorized` type with the revocation rejection."""
    deadline = time.monotonic() + timeout_s
    status, body = 0, b""
    while True:
        status, body = _acme_update_contact(ctx, account, contact)
        if status != 403 or _ROLE_ASSUME_FAILURE not in body:
            return status, body
        if time.monotonic() >= deadline:
            return status, body
        time.sleep(interval_s)


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
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
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
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
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


def _described_contacts(acm, endpoint_arn, account_url):
    return (
        acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)[
            "AcmeAccount"
        ].get("Contacts")
        or []
    )


# Hand-rolled RFC 8555 client: the `acme` PyPI client's update_registration fails client-side
# against ACM, because ACM echoes `externalAccountBinding` in the newAccount response and josepy
# cannot re-serialize it.


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jws(protected: dict, payload_bytes: bytes, sign_fn) -> dict:
    protected_b64 = _b64url(json.dumps(protected).encode())
    payload_b64 = _b64url(payload_bytes)
    signature = sign_fn(f"{protected_b64}.{payload_b64}".encode())
    return {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature)}


def _acme_directory(ctx, endpoint_url: str) -> dict:
    with urllib.request.urlopen(_routed_request(ctx, endpoint_url), timeout=30) as resp:
        return json.loads(resp.read())


def _fetch_nonce(ctx, directory: dict) -> str:
    req = _routed_request(ctx, directory["newNonce"], method="HEAD")
    with urllib.request.urlopen(req, timeout=30) as resp:
        nonce = resp.headers.get("Replay-Nonce")
    if not nonce:
        raise AssertionError("ACME server did not return a Replay-Nonce")
    return nonce


def _post_jose(ctx, url: str, body: bytes) -> tuple[int, bytes]:
    req = _routed_request(ctx,
        url, data=body, headers={"Content-Type": "application/jose+json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _register_acme_account(ctx, directory: dict, key_id: str, mac_key_b64: str) -> dict:
    """Register a fresh real ACME account; returns a handle that can sign further writes as it."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    new_account_url = directory["newAccount"]
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }

    def _sign_es256(data: bytes) -> bytes:
        r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    # RFC 8555 7.3.4: the EAB JWS payload is the account's PUBLIC key in JWK form, MAC'd with
    # the ACM-issued MacKey. ACM answers that MacKey in the base64url alphabet.
    mac_key = _b64url_decode(mac_key_b64)
    eab_jws = _jws(
        {"alg": "HS256", "kid": key_id, "url": new_account_url},
        json.dumps(jwk).encode(),
        lambda data: hmac.new(mac_key, data, hashlib.sha256).digest(),
    )
    payload = json.dumps(
        {"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}
    ).encode()

    for attempt in range(2):
        outer = {
            "alg": "ES256",
            "jwk": jwk,
            "nonce": _fetch_nonce(ctx, directory),
            "url": new_account_url,
        }
        req = _routed_request(ctx,
            new_account_url,
            data=json.dumps(_jws(outer, payload, _sign_es256)).encode(),
            headers={"Content-Type": "application/jose+json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                account_url = resp.headers.get("Location")
                if not account_url:
                    raise AssertionError("ACME newAccount response missing Location header")
                return {"account_url": account_url, "sign": _sign_es256, "directory": directory}
        except urllib.error.HTTPError as exc:
            body = exc.read()
            if attempt == 0 and exc.code == 400 and b"badNonce" in body:
                continue
            raise AssertionError(f"ACME newAccount failed ({exc.code}): {body!r}") from exc
    raise AssertionError("ACME newAccount failed after a badNonce retry")


def _acme_update_contact(ctx, account: dict, contact: str) -> tuple[int, bytes]:
    """RFC 8555 7.3.2 account update, signed with `kid` (the account URL) as this account.

    Returns (http_status, body) rather than raising, because BOTH outcomes are verdicts here.
    """
    directory = account["directory"]
    url = account["account_url"]
    payload = json.dumps({"contact": [contact]}).encode()
    status, body = 0, b""
    for attempt in range(2):
        outer = {
            "alg": "ES256",
            "kid": url,
            "nonce": _fetch_nonce(ctx, directory),
            "url": url,
        }
        status, body = _post_jose(ctx,
            url, json.dumps(_jws(outer, payload, account["sign"])).encode()
        )
        if attempt == 0 and status == 400 and b"badNonce" in body:
            continue
        break
    return status, body


def _acme_problem_type(body: bytes) -> str | None:
    """The RFC 7807 / RFC 8555 problem document's `type` URN verbatim, or None if absent."""
    try:
        return json.loads(body).get("type")
    except (ValueError, AttributeError):
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
