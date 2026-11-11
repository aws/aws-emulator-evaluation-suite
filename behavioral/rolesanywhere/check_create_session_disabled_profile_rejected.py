"""create-session-disabled-profile-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-session-disabled-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The X.509-signed CreateSession call against a disabled profile is refused with HTTP 403
    AccessDeniedException and vends no credentials, while the same request succeeds with the profile
    enabled, before the disable and again after re-enabling it.
    """
    ca_key, ca_cert, ca_pem = _generate_ca(ctx.unique_name("sim2real-ra-ca-"))
    leaf_key, leaf_cert = _generate_leaf(ca_key, ca_cert, ctx.unique_name("sim2real-ra-leaf-"))

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ra-sess-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rolesanywhere.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        enabled=True,
    )["trustAnchor"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta["trustAnchorId"]))

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-sess-profile-"),
        roleArns=[role["Arn"]],
        enabled=True,
    )["profile"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile["profileId"]))

    body = {
        "profileArn": profile["profileArn"],
        "roleArn": role["Arn"],
        "trustAnchorArn": ta["trustAnchorArn"],
    }

    # Positive control: enabled profile, signed request succeeds.
    control = _poll_create_session(ctx, leaf_key, leaf_cert, body, timeout_s=90.0)
    assert control["status"] == 201, control["body"]
    assert len(control["body"]["credentialSet"]) == 1, (
        f"expected exactly one credential set while the profile is enabled, "
        f"got {control['body'].get('credentialSet')}"
    )

    ra.disable_profile(profileId=profile["profileId"])
    got = ra.get_profile(profileId=profile["profileId"])["profile"]
    assert got["enabled"] is False, f"expected disable_profile to flip enabled to False, got {got['enabled']!r}"

    # Same signed-request shape, disabled profile: rejected, no credentials.
    denied = _poll_for_stable_non_201(ctx, leaf_key, leaf_cert, body, timeout_s=60.0)
    assert denied["status"] == 403, f"expected 403 for a disabled profile, got status={denied['status']} body={denied['body']}"
    # x-amzn-ErrorType carries the error code followed by a colon and a URL; only the part
    # before the colon is the error code.
    denied_error_code = denied["error_type"].split(":", 1)[0]
    assert denied_error_code == "AccessDeniedException", (
        f"expected error code AccessDeniedException, got {denied_error_code!r} "
        f"(raw error_type={denied['error_type']!r}) body={denied['body']}"
    )
    assert "credentialSet" not in denied["body"], f"disabled profile must not vend credentials, got body={denied['body']}"

    # Restore leg: re-enable the profile and demand the identical signed
    # request succeeds again, unchanged.
    ra.enable_profile(profileId=profile["profileId"])
    got = ra.get_profile(profileId=profile["profileId"])["profile"]
    assert got["enabled"] is True, f"expected enable_profile to flip enabled back to True, got {got['enabled']!r}"

    restored = _poll_create_session(ctx, leaf_key, leaf_cert, body, timeout_s=90.0)
    assert restored["status"] == 201, (
        f"expected the identical signed request to succeed once the profile is re-enabled, "
        f"got status={restored['status']} body={restored['body']}"
    )
    assert len(restored["body"]["credentialSet"]) == 1, (
        f"expected exactly one credential set after re-enabling, got {restored['body'].get('credentialSet')}"
    )


def _generate_ca(common_name: str):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key, cert, pem


def _generate_leaf(ca_key, ca_cert, common_name: str):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return leaf_key, leaf_cert


def _create_session_via_x509(ctx, leaf_key, leaf_cert, body: dict) -> dict:
    import base64
    import datetime
    import hashlib
    import urllib.error
    import urllib.parse
    import urllib.request

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    client = ctx.client("rolesanywhere")
    endpoint = client.meta.endpoint_url.rstrip("/")
    url = endpoint + "/sessions"
    host = urllib.parse.urlparse(endpoint).netloc

    payload = json.dumps(body).encode("utf-8")
    amz_date = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    x509_b64 = base64.b64encode(leaf_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")

    headers = {
        "content-type": "application/json",
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-x509": x509_b64,
    }
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    signed_headers = ";".join(sorted(headers.keys()))
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_request = (
        "POST\n/sessions\n\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash
    )
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

    credential_scope = f"{date_stamp}/{ctx.region}/rolesanywhere/aws4_request"
    algorithm = "AWS4-X509-RSA-SHA256"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashed_canonical_request}"
    signature = leaf_key.sign(string_to_sign.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()).hex()
    credential = f"{leaf_cert.serial_number}/{credential_scope}"
    authorization = f"{algorithm} Credential={credential}, SignedHeaders={signed_headers}, Signature={signature}"

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Amz-Date": amz_date,
            "X-Amz-X509": x509_b64,
            "Authorization": authorization,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return {"status": resp.status, "body": json.loads(resp.read().decode("utf-8")), "error_type": ""}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            parsed = {"raw": raw.decode("utf-8", "replace")}
        error_type = exc.headers.get("x-amzn-ErrorType", "") if exc.headers else ""
        return {"status": exc.code, "body": parsed, "error_type": error_type}


def _poll_create_session(ctx, leaf_key, leaf_cert, body, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    while last["status"] != 201 and time.monotonic() < deadline:
        # IAM role trust policy / trust anchor propagation can lag briefly.
        time.sleep(3)
        last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    return last


def _poll_for_stable_non_201(ctx, leaf_key, leaf_cert, body, timeout_s: float) -> dict:
    # Disabling a profile is expected to take effect promptly, but poll briefly
    # in case of read-after-write lag on the disable itself.
    deadline = time.monotonic() + timeout_s
    last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    while last["status"] == 201 and time.monotonic() < deadline:
        time.sleep(3)
        last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
