"""import-key-material-valid-to-timestamp-preserved."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from behavioral_harness import tags

CHECK = "import-key-material-valid-to-timestamp-preserved"
GROUP = "representation"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The ValidTo passed to ImportKeyMaterial with KEY_MATERIAL_EXPIRES is returned exactly, to the
    second, by DescribeKey, and ExpirationModel stays KEY_MATERIAL_EXPIRES."""
    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-import-validto-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-valid-to-timestamp-preserved"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)
    encrypted_material = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # The wire format is epoch seconds, so only whole seconds can round-trip exactly.
    valid_to = (datetime.now(timezone.utc) + timedelta(days=3)).replace(microsecond=0)

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=encrypted_material,
        ExpirationModel="KEY_MATERIAL_EXPIRES",
        ValidTo=valid_to,
    )

    described = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert described["ExpirationModel"] == "KEY_MATERIAL_EXPIRES", (
        f"ExpirationModel round-tripped as {described['ExpirationModel']!r}, expected "
        "'KEY_MATERIAL_EXPIRES'"
    )
    assert described["ValidTo"] == valid_to, (
        f"ValidTo round-tripped as {described['ValidTo']!r}, expected exactly {valid_to!r}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
