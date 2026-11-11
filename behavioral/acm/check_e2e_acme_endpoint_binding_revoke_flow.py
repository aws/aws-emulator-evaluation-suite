"""e2e-acme-endpoint-binding-revoke-flow."""
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


CHECK = "e2e-acme-endpoint-binding-revoke-flow"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ACME account registered through the endpoint's directory reaches REVOKED when revoked;
    the deleted domain validation stops listing, and the deleted EAB and endpoint then fail
    Describe with ResourceNotFoundException."""
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401

    acm = ctx.client("acm")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-acm-eab-role-")
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
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                "Resource": "*",
            }
        ],
    }
    policy_name = ctx.unique_name("sim2real-acm-eab-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )


    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    endpoint = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"],
        lambda e: e["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert endpoint["Status"] == "ACTIVE", f"endpoint failed to activate: {endpoint.get('FailureReason')}"
    endpoint_url = endpoint["EndpointUrl"]

    domain = f"{_dns_label(ctx.unique_name('sim2real-acme'))}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeDomainValidationArn"]

    # The new role and its PassRole grant propagate eventually: retry the create on the
    # propagation refusals to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60 if left is None else min(60, left))
    while True:
        try:
            eab = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            eab_arn = eab["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {exc}") from exc
            time.sleep(2)

    account_url = _acme_register_account(ctx, acm, endpoint_url, eab_arn)


    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    account = _poll_until(
        lambda: acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"],
        lambda a: a["Status"] == "REVOKED",
        timeout_s=60,
        interval_s=3,
    )
    assert account["Status"] == "REVOKED", f"expected AcmeAccount REVOKED, got {account['Status']!r}"

    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    def _validation_gone() -> bool:
        arns = [
            v["AcmeDomainValidationArn"]
            for v in acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn).get(
                "AcmeDomainValidations", []
            )
        ]
        return dv_arn not in arns

    validation_gone = _poll_until(_validation_gone, lambda gone: gone, timeout_s=60, interval_s=3)
    assert validation_gone, f"domain validation {dv_arn} still listed after DeleteAcmeDomainValidation"

    eab_deleted_code, eab_deleted_message = _wait_until_refused(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn),
        timeout_s=60,
        interval_s=3,
    )
    assert eab_deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing deleted EAB {eab_arn}, got {eab_deleted_code!r}"
    )
    expected_message = f"Could not find ACME external account binding {eab_arn}."
    assert eab_deleted_message == expected_message, (
        f"expected message {expected_message!r}, got {eab_deleted_message!r}"
    )

    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    deleted_code, deleted_message = _wait_until_refused(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn),
        timeout_s=60,
        interval_s=3,
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing deleted endpoint {endpoint_arn}, got {deleted_code!r}"
    )
    expected_message = f"Could not find ACME endpoint {endpoint_arn}."
    assert deleted_message == expected_message, (
        f"expected message {expected_message!r}, got {deleted_message!r}"
    )


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_until_refused(fn, timeout_s=60.0, interval_s=2.0):
    """Call fn until it is refused; return the refusal's (code, message).

    A call that keeps succeeding past the deadline raises: the resource never went away."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"call still succeeded after {timeout_s}s (last response: {last!r})")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _acme_get_json(ctx, url: str):
    with urllib.request.urlopen(_routed_request(ctx, url, method="GET"), timeout=30) as resp:
        return json.loads(resp.read().decode())


def _acme_new_nonce(ctx, url: str) -> str:
    req = _routed_request(ctx, url, method="HEAD")
    with urllib.request.urlopen(req, timeout=30) as resp:
        nonce = resp.headers.get("Replay-Nonce")
    if not nonce:
        raise AssertionError("ACME server did not return a Replay-Nonce")
    return nonce


def _acme_post(ctx, url: str, jws_body: dict):
    data = json.dumps(jws_body).encode()
    req = _routed_request(ctx,
        url, data=data, method="POST", headers={"Content-Type": "application/jose+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else {}), resp.headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        return exc.code, (json.loads(body) if body else {}), exc.headers


def _rsa_jwk(public_key) -> dict:
    numbers = public_key.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "n": _b64url(n), "e": _b64url(e)}


def _rs256_jws(private_key, protected: dict, payload_bytes: bytes) -> dict:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    protected_b64 = _b64url(json.dumps(protected).encode())
    payload_b64 = _b64url(payload_bytes)
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature)}


def _hs256_jws(mac_key: bytes, protected: dict, payload_bytes: bytes) -> dict:
    protected_b64 = _b64url(json.dumps(protected).encode())
    payload_b64 = _b64url(payload_bytes)
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    signature = hmac.new(mac_key, signing_input, hashlib.sha256).digest()
    return {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature)}


def _acme_register_account(ctx, acm, endpoint_url: str, eab_arn: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa

    directory = _acme_get_json(ctx, endpoint_url)
    new_account_url = directory["newAccount"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _rsa_jwk(key.public_key())
    payload = {"termsOfServiceAgreed": True, "contact": ["mailto:sim2real-acm-check@example.com"]}
    payload_bytes = json.dumps(payload).encode()

    nonce = _acme_new_nonce(ctx, directory["newNonce"])
    protected = {"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": new_account_url}
    status, resp_body, headers = _acme_post(ctx, new_account_url, _rs256_jws(key, protected, payload_bytes))

    if status == 400 and "externalaccountrequired" in json.dumps(resp_body).lower():
        creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
        key_id = creds["KeyId"]
        mac_key = base64.urlsafe_b64decode(creds["MacKey"] + "===")
        eab_protected = {"alg": "HS256", "kid": key_id, "url": new_account_url}
        eab_jws = _hs256_jws(mac_key, eab_protected, json.dumps(jwk).encode())
        payload["externalAccountBinding"] = eab_jws
        payload_bytes = json.dumps(payload).encode()
        nonce = _acme_new_nonce(ctx, directory["newNonce"])
        protected = {"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": new_account_url}
        status, resp_body, headers = _acme_post(ctx, new_account_url, _rs256_jws(key, protected, payload_bytes))

    if status not in (200, 201):
        raise AssertionError(f"ACME newAccount failed: status={status} body={resp_body}")
    account_url = headers.get("Location")
    if not account_url:
        raise AssertionError("ACME newAccount response had no Location header")
    return account_url


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
