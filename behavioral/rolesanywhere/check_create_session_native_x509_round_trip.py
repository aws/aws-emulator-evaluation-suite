"""create-session-native-x509-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-session-native-x509-round-trip"
GROUP = "native-protocol"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A raw CreateSession request signed with an X.509 leaf certificate vends credentials for the
    profile's role, named by the certificate's hex serial number, and sts:GetCallerIdentity with
    them resolves to that role.
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        enabled=True,
        tags=[{"key": "sim2real", "value": "true"}],
    )["trustAnchor"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta["trustAnchorId"]))

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-sess-profile-"),
        roleArns=[role["Arn"]],
        enabled=True,
        tags=[{"key": "sim2real", "value": "true"}],
    )["profile"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile["profileId"]))

    body = {
        "profileArn": profile["profileArn"],
        "roleArn": role["Arn"],
        "trustAnchorArn": ta["trustAnchorArn"],
    }

    result = _poll_create_session(ctx, leaf_key, leaf_cert, body, timeout_s=90.0)
    assert result["status"] == 201, result["body"]

    credential_set = result["body"]["credentialSet"]
    assert len(credential_set) == 1, f"expected exactly 1 vended credential set, got {credential_set}"
    entry = credential_set[0]
    assert entry["roleArn"] == role["Arn"], f"expected roleArn {role['Arn']!r}, got {entry['roleArn']!r}"
    # The default role session name (no roleSessionName supplied) is the signing
    # certificate's serial number, hex-encoded (not decimal, not a SHA-1 fingerprint).
    expected_session_name = format(leaf_cert.serial_number, "x")
    assert entry["assumedRoleUser"]["arn"].endswith(f"/{expected_session_name}"), (
        f"expected assumedRoleUser arn to end with '/{expected_session_name}' "
        f"(hex-encoded serial number of the signing certificate), got {entry['assumedRoleUser']['arn']!r}"
    )

    creds = entry["credentials"]
    sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )
    identity = sts.get_caller_identity()
    assert f":assumed-role/{role_name}/" in identity["Arn"], (
        f"expected the vended session credentials to resolve to an assumed-role "
        f"identity for {role_name!r}, got {identity['Arn']!r}"
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
        with urllib.request.urlopen(req, timeout=30, context=_tls_context(ctx)) as resp:
            return {"status": resp.status, "body": json.loads(resp.read().decode("utf-8")), "error_type": ""}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            parsed = {"raw": raw.decode("utf-8", "replace")}
        error_type = exc.headers.get("x-amzn-ErrorType", "") if exc.headers else ""
        return {"status": exc.code, "body": parsed, "error_type": error_type}


def _tls_context(ctx):
    """The TLS context for this check's own HTTPS call, verified the way ``ctx.http_verify`` says."""
    import ssl

    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _poll_create_session(ctx, leaf_key, leaf_cert, body, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    while last["status"] != 201 and time.monotonic() < deadline:
        # IAM role trust policy / trust anchor propagation can lag briefly.
        time.sleep(3)
        last = _create_session_via_x509(ctx, leaf_key, leaf_cert, body)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
