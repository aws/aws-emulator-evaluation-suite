"""acme-account-revoke-lifecycle."""
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


CHECK = "acme-account-revoke-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ACME account visible via Describe/List transitions to REVOKED after RevokeAcmeAccount."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import hashes

    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]

    role_arn = _create_acme_role(ctx)
    eab = _pass_role_with_retry(
        lambda: acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
    )["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )
    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    key_id = creds["KeyId"]
    mac_key_bytes = _b64url_decode(creds["MacKey"])

    account_url = _acme_register_account(ctx, endpoint_url, key_id, mac_key_bytes, padding, rsa, hashes)
    if account_url is None:
        raise AssertionError("unreachable: ACME newAccount registration against the live endpoint did not complete")

    # The registered account is now real AWS state, visible via the ACM control plane.
    desc = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert desc["AccountUrl"] == account_url, f"expected AccountUrl {account_url}, got {desc['AccountUrl']}"
    assert desc["Status"] == "VALID", f"expected freshly-registered account VALID, got {desc['Status']}"
    assert desc["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected AcmeExternalAccountBindingArn {eab_arn}, got {desc['AcmeExternalAccountBindingArn']}"
    )

    assert _find_account(acm, endpoint_arn, account_url) is not None, "account missing from ListAcmeAccounts"

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    desc2 = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert desc2["Status"] == "REVOKED", f"expected REVOKED after RevokeAcmeAccount, got {desc2['Status']}"

    # RevokeAcmeAccount has no state-conflict precondition: re-revoking an already-revoked
    # account succeeds idempotently (no ConflictException) and must not resurrect or otherwise
    # mutate the terminal state. Any error the second call raises propagates and fails the check.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    desc3 = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert desc3["Status"] == "REVOKED", f"idempotent re-revoke must leave status REVOKED, got {desc3['Status']}"


def _pass_role_with_retry(fn, attempts=15, interval_s=3.0):
    """Call fn(), retrying while a freshly created role is not yet passable.

    iam:PassRole on a role created moments earlier is refused with AccessDeniedException until
    the role propagates through IAM; a refusal that outlasts the bounded retry raises."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or "PassRole" not in str(exc):
                raise
            last = exc
            time.sleep(interval_s)
    raise AssertionError(
        "this identity could not pass the check's role to ACM within the retry window "
        f"(CreateAcmeExternalAccountBinding requires iam:PassRole on RoleArn); {last}"
    )


def _create_active_endpoint(ctx, acm):
    name = ctx.unique_name("sim2real-behav-acme-ep-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _wait_for_status(acm, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
    return arn


def _create_acme_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-acme-role-")
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acme-issue")))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="acme-issue",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"], "Resource": "*"}
                ],
            }
        ),
    )
    return role_arn


def _wait_for_status(acm, arn, terminal_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    return last


def _find_account(acm, endpoint_arn, account_url):
    kwargs = {"AcmeEndpointArn": endpoint_arn}
    while True:
        resp = acm.list_acme_accounts(**kwargs)
        for a in resp.get("AcmeAccounts", []):
            if a.get("AccountUrl") == account_url:
                return a
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs = {"AcmeEndpointArn": endpoint_arn, "NextToken": token}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding_needed = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * padding_needed))


def _http_json(ctx, url, data=None, method="GET", headers=None):
    req = _routed_request(ctx, url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read()
        return resp.status, dict(resp.headers), body


def _acme_register_account(ctx, endpoint_url, key_id, mac_key_bytes, padding, rsa, hashes):
    """Best-effort minimal RFC 8555 newAccount registration with external account binding.

    Returns the registered Account URL, or None when the directory, nonce or newAccount answer
    is not a success; transport errors propagate.
    """
    status, _, body = _http_json(ctx, endpoint_url)
    if status != 200:
        return None
    directory = json.loads(body)
    new_nonce_url = directory["newNonce"]
    new_account_url = directory["newAccount"]

    req = _routed_request(ctx, new_nonce_url, method="HEAD")
    with urllib.request.urlopen(req, timeout=20) as resp:
        nonce = resp.headers.get("Replay-Nonce")
    if not nonce:
        return None

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_numbers = private_key.public_key().public_numbers()
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    jwk = {"kty": "RSA", "n": _b64url(n_bytes), "e": _b64url(e_bytes)}

    # Inner JWS: EAB, HMAC-signed with the ACM-issued MAC key, keyed by KeyId.
    eab_protected = {"alg": "HS256", "kid": key_id, "url": new_account_url}
    eab_protected_b64 = _b64url(json.dumps(eab_protected, separators=(",", ":")).encode())
    eab_payload_b64 = _b64url(json.dumps(jwk, separators=(",", ":")).encode())
    eab_signing_input = f"{eab_protected_b64}.{eab_payload_b64}".encode()
    eab_sig = hmac.new(mac_key_bytes, eab_signing_input, hashlib.sha256).digest()
    eab_jws = {
        "protected": eab_protected_b64,
        "payload": eab_payload_b64,
        "signature": _b64url(eab_sig),
    }

    # Outer JWS: account-key-signed newAccount request carrying the EAB.
    outer_payload = {"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}
    outer_protected = {"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": new_account_url}
    outer_protected_b64 = _b64url(json.dumps(outer_protected, separators=(",", ":")).encode())
    outer_payload_b64 = _b64url(json.dumps(outer_payload, separators=(",", ":")).encode())
    outer_signing_input = f"{outer_protected_b64}.{outer_payload_b64}".encode()
    signature = private_key.sign(outer_signing_input, padding.PKCS1v15(), hashes.SHA256())
    outer_jws = {
        "protected": outer_protected_b64,
        "payload": outer_payload_b64,
        "signature": _b64url(signature),
    }

    req = _routed_request(ctx,
        new_account_url,
        data=json.dumps(outer_jws).encode(),
        method="POST",
        headers={"Content-Type": "application/jose+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status not in (200, 201):
                return None
            return resp.headers.get("Location")
    except urllib.error.HTTPError:
        return None


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
