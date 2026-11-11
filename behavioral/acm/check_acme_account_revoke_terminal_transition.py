"""acme-account-revoke-terminal-transition."""
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


CHECK = "acme-account-revoke-terminal-transition"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """RevokeAcmeAccount moves an ACME account registered over RFC 8555 to a terminal REVOKED state
    that DescribeAcmeAccount reflects, while Describe and Revoke on a never-registered AccountUrl of
    the same endpoint raise ResourceNotFoundException and change nothing."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    iam = ctx.client("iam")

    endpoint_arn, endpoint_url = _create_acme_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx, iam)
    eab_arn, creds = _create_eab(ctx, acm, endpoint_arn, role_arn)

    account_url = _acme_register_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])
    valid = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert valid["Status"] == "VALID", f"newly registered account was not VALID: {valid}"

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    revoked = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert revoked["Status"] == "REVOKED", f"expected REVOKED after revoke, got {revoked['Status']}"

    missing_account_url = (
        "https://acm-acme-enroll.example.invalid/directory/acct/"
        "00000000-0000-0000-0000-000000000000"
    )

    expected_message = f"Could not find ACME account {missing_account_url}."
    describe_code, describe_message = _error_code(
        lambda: acm.describe_acme_account(
            AcmeEndpointArn=endpoint_arn, AccountUrl=missing_account_url
        )
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing an unregistered account, got {describe_code!r}"
    )
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    revoke_code, revoke_message = _error_code(
        lambda: acm.revoke_acme_account(
            AcmeEndpointArn=endpoint_arn, AccountUrl=missing_account_url
        )
    )
    assert revoke_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException revoking an unregistered account, got {revoke_code!r}"
    )
    assert revoke_message == expected_message, f"expected message {expected_message!r}, got {revoke_message!r}"

    # effect absent: the rejected calls did not touch the endpoint they were scoped to, nor
    # the real account that already reached its own terminal state.
    still_endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert still_endpoint["Status"] == "ACTIVE", (
        f"endpoint status changed after the rejected calls: {still_endpoint['Status']}"
    )
    still_account = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert still_account["Status"] == "REVOKED", (
        f"real account status changed after the rejected calls: {still_account['Status']}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_acme_endpoint(ctx, acm) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-acme-ep-")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    endpoint = _wait_for_endpoint_terminal(ctx, arn)
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {endpoint['Status']}, expected ACTIVE")
    return arn, endpoint["EndpointUrl"]


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Status"] in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _create_eab_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-behav-acme-role-")
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
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore_errors(ctx, name))
    policy_name = "acme-issue"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_ignore_errors(ctx, name, policy_name))
    return role_arn


def _delete_role_ignore_errors(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy_ignore_errors(ctx, name: str, policy_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_eab(ctx, acm, endpoint_arn: str, role_arn: str) -> tuple[str, dict]:
    last_err = None
    for _ in range(12):
        try:
            resp = acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
            eab_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(lambda arn=eab_arn: _delete_eab_ignore_errors(ctx, arn))
            creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
            return eab_arn, creds
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err}")


def _delete_eab_ignore_errors(ctx, arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _http(ctx, url: str, *, data: bytes | None = None, headers: dict | None = None, method: str = "GET"):
    req = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _acme_register_account(ctx, endpoint_url: str, eab_key_id: str, eab_mac_key: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    status, _, body = _http(ctx, endpoint_url)
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

    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    new_account_url = directory["newAccount"]

    mac_key = _b64url_decode(eab_mac_key)
    eab_protected = _b64url(json.dumps({"alg": "HS256", "kid": eab_key_id, "url": new_account_url}).encode())
    eab_payload = _b64url(json.dumps(jwk).encode())
    eab_sig = _b64url(hmac.new(mac_key, f"{eab_protected}.{eab_payload}".encode(), hashlib.sha256).digest())
    eab_jws = {"protected": eab_protected, "payload": eab_payload, "signature": eab_sig}

    outer_protected = _b64url(
        json.dumps({"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": new_account_url}).encode()
    )
    outer_payload = _b64url(
        json.dumps({"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}).encode()
    )
    signing_input = f"{outer_protected}.{outer_payload}".encode()
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
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
