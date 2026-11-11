"""generate-mac-equals-a-locally-computed-hmac-over-the-imported-key-material."""
from __future__ import annotations

import hashlib
import hmac
import os
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from behavioral_harness import tags

CHECK = "generate-mac-equals-a-locally-computed-hmac-over-the-imported-key-material"
GROUP = "hmac"
SERVICES = ["kms"]

# (KeySpec, MacAlgorithm, material length in bytes, local hashlib constructor). Material is
# exactly the key-spec length, which every AWS page on HMAC import accepts.
_CASES = (
    ("HMAC_256", "HMAC_SHA_256", 32, hashlib.sha256),
    ("HMAC_512", "HMAC_SHA_512", 64, hashlib.sha512),
)


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return  # already PendingDeletion
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or RAISES on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _wrap_for_import(public_key_der: bytes, material: bytes) -> bytes:
    """RSAES_OAEP_SHA_256-wrap `material` under the DER wrapping key GetParametersForImport gave."""
    pub = serialization.load_der_public_key(public_key_der)
    assert pub.key_size == 2048, f"WrappingKeySpec RSA_2048 must be 2048-bit, got {pub.key_size}"
    return pub.encrypt(
        material,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMac on imported HMAC_256/HMAC_512 keys equals a local RFC 2104 HMAC over the
    imported bytes, and VerifyMac accepts a locally computed MAC over a message KMS never saw.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html
    """
    kms = ctx.client("kms")

    verified = []
    for key_spec, mac_alg, material_len, hasher in _CASES:
        material = os.urandom(material_len)
        assert len(material) == material_len, len(material)

        meta = kms.create_key(
            Description=ctx.unique_name(f"sim2real-behav-kms-hmacimport-{key_spec.lower()}-"),
            KeyUsage="GENERATE_VERIFY_MAC",
            KeySpec=key_spec,
            Origin="EXTERNAL",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-hmac-local-recomputation"}],
        )["KeyMetadata"]
        key_arn = meta["Arn"]
        ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
        assert meta["Origin"] == "EXTERNAL", (
            f"{key_spec}: an import-origin key must report Origin EXTERNAL, got "
            f"{meta['Origin']!r}"
        )
        assert meta["KeyState"] == "PendingImport", (
            f"{key_spec}: a key with no material yet must be PendingImport, got "
            f"{meta['KeyState']!r}"
        )
        assert meta["MacAlgorithms"] == [mac_alg], (
            f"{key_spec} must advertise exactly [{mac_alg!r}], got {meta['MacAlgorithms']!r}"
        )

        params = kms.get_parameters_for_import(
            KeyId=key_arn, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
        kms.import_key_material(
            KeyId=key_arn,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=_wrap_for_import(params["PublicKey"], material),
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
        # Import is applied asynchronously; the key is unusable until it leaves PendingImport.
        _poll_until(
            lambda _a=key_arn: kms.describe_key(KeyId=_a)["KeyMetadata"]["KeyState"],
            lambda state: state == "Enabled",
            timeout_s=60,
            what=f"{key_arn} to reach Enabled after ImportKeyMaterial",
        )

        # A fresh random message, so the MAC cannot have been precomputed.
        message = b"kms-hmac-local-oracle-" + os.urandom(32)

        got = kms.generate_mac(KeyId=key_arn, Message=message, MacAlgorithm=mac_alg)
        kms_mac = got["Mac"]
        assert got["MacAlgorithm"] == mac_alg, (
            f"{key_spec}: GenerateMac must echo MacAlgorithm {mac_alg!r}, got "
            f"{got['MacAlgorithm']!r}"
        )
        assert got["KeyId"] == key_arn, (
            f"{key_spec}: GenerateMac must report the key ARN {key_arn!r}, got {got['KeyId']!r}"
        )

        # Recompute the MAC off AWS from the imported bytes.
        expected = hmac.new(material, message, hasher).digest()
        assert len(expected) == hasher().digest_size, (len(expected), hasher().digest_size)
        assert kms_mac == expected, (
            f"{key_spec}: GenerateMac must return RFC 2104 HMAC over the imported material. "
            f"expected {expected.hex()[:48]}... ({len(expected)}B), actual "
            f"{kms_mac.hex()[:48]}... ({len(kms_mac)}B)"
        )

        # Proves the local computation is key-dependent.
        wrong_key = bytearray(material)
        wrong_key[0] ^= 0x01
        off_by_one_bit = hmac.new(bytes(wrong_key), message, hasher).digest()
        assert off_by_one_bit != kms_mac, (
            f"{key_spec}: a one-bit change to the key must change the local HMAC — the local "
            f"oracle is not reading the key material at all"
        )

        # VerifyMac over a second message that was never sent to GenerateMac.
        unseen = b"never-macced-by-kms-" + os.urandom(32)
        assert unseen != message, (unseen, message)
        local_only_mac = hmac.new(material, unseen, hasher).digest()
        verdict = kms.verify_mac(
            KeyId=key_arn, Message=unseen, MacAlgorithm=mac_alg, Mac=local_only_mac
        )
        assert verdict["MacValid"] is True, (
            f"{key_spec}: VerifyMac must accept a MAC computed outside KMS from the imported "
            f"material over a message KMS has never MAC'd; got {verdict!r}"
        )
        assert verdict["KeyId"] == key_arn, (
            f"{key_spec}: VerifyMac must report {key_arn!r}, got {verdict['KeyId']!r}"
        )

        # The same tag must not verify against the first message: KMS checks the tag.
        code, err_message = _error(
            lambda _a=key_arn, _m=message, _t=local_only_mac: kms.verify_mac(
                KeyId=_a, Message=_m, MacAlgorithm=mac_alg, Mac=_t
            )
        )
        assert code == "KMSInvalidMacException", (
            f"{key_spec}: the locally computed tag for a different message must be refused with "
            f"KMSInvalidMacException, got {code!r}"
        )
        # AWS sends KMSInvalidMacException with an empty message.
        assert err_message == "", f"{key_spec}: unexpected message: {err_message!r}"

        verified.append(key_spec)

    assert verified == ["HMAC_256", "HMAC_512"], (
        f"both key specs must have been exercised, got {verified!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
