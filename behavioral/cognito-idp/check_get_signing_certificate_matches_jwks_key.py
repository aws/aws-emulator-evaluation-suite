"""get-signing-certificate-matches-jwks-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-signing-certificate-matches-jwks-key"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetSigningCertificate returns a certificate whose RSA public key (modulus) matches one of
    the keys published at the pool's own JWKS endpoint -- the two must describe the same signing
    key pair, not independently-generated values."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    cert_pem = cognito.get_signing_certificate(UserPoolId=pool_id)["Certificate"]
    cert_modulus = _extract_certificate_modulus(cert_pem)

    endpoint = cognito.meta.endpoint_url.rstrip("/")
    jwks_url = f"{endpoint}/{pool_id}/.well-known/jwks.json"
    jwks_moduli = _jwks_moduli(jwks_url)

    assert jwks_moduli, "JWKS document contained no keys"
    assert cert_modulus in jwks_moduli, (
        f"signing certificate's RSA modulus was not among the {len(jwks_moduli)} JWKS key "
        f"modulus/moduli published for pool {pool_id!r} -- cert and JWKS must describe the "
        f"same key pair"
    )


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _walk_der_bitstrings(data: bytes) -> list:
    """Recursively collect the content of every primitive BIT STRING TLV in a DER blob."""
    results: list = []

    def parse(buf: bytes, start: int, end: int) -> None:
        pos = start
        while pos < end:
            tag = buf[pos]
            pos += 1
            first_len = buf[pos]
            pos += 1
            if first_len & 0x80:
                num_bytes = first_len & 0x7F
                length = int.from_bytes(buf[pos : pos + num_bytes], "big")
                pos += num_bytes
            else:
                length = first_len
            content_start = pos
            content_end = pos + length
            if tag == 0x03:
                results.append(buf[content_start:content_end])
            if tag & 0x20:  # constructed: recurse to find nested TLVs
                parse(buf, content_start, content_end)
            pos = content_end

    parse(data, 0, len(data))
    return results


def _try_parse_rsa_modulus(bitstring_content: bytes):
    """If this BIT STRING's payload is a DER SEQUENCE(INTEGER modulus, INTEGER exponent)
    (an RSAPublicKey), return the modulus as an int; otherwise return None."""
    if len(bitstring_content) < 2:
        return None
    body = bitstring_content[1:]  # drop the "unused bits" byte
    if not body or body[0] != 0x30:
        return None
    pos = 1
    if pos >= len(body):
        return None
    first_len = body[pos]
    pos += 1
    if first_len & 0x80:
        pos += first_len & 0x7F
    if pos >= len(body) or body[pos] != 0x02:
        return None
    pos += 1
    if pos >= len(body):
        return None
    int_len_byte = body[pos]
    pos += 1
    if int_len_byte & 0x80:
        num_bytes = int_len_byte & 0x7F
        int_len = int.from_bytes(body[pos : pos + num_bytes], "big")
        pos += num_bytes
    else:
        int_len = int_len_byte
    modulus_bytes = body[pos : pos + int_len]
    if len(modulus_bytes) != int_len:
        return None
    return int.from_bytes(modulus_bytes, "big")


def _extract_certificate_modulus(cert_field: str) -> int:
    import base64

    if "-----BEGIN" in cert_field:
        lines = [line.strip() for line in cert_field.splitlines() if line and "-----" not in line]
        der_b64 = "".join(lines)
    else:
        der_b64 = cert_field.strip()
    der = base64.b64decode(der_b64)
    for candidate in _walk_der_bitstrings(der):
        modulus = _try_parse_rsa_modulus(candidate)
        if modulus is not None:
            return modulus
    raise AssertionError("could not locate an RSA modulus in the signing certificate")


def _jwks_moduli(jwks_url: str) -> list:
    import base64
    import json
    import urllib.request

    with urllib.request.urlopen(jwks_url, timeout=15) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    moduli = []
    for key in doc.get("keys", []):
        n_b64 = key["n"]
        padded = n_b64 + "=" * (-len(n_b64) % 4)
        moduli.append(int.from_bytes(base64.urlsafe_b64decode(padded), "big"))
    return moduli


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
