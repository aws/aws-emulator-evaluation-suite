"""put-get-encryption-config-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-get-encryption-config-transitions"
GROUP = 'encryption-config'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observed: {last!r}"
            )
        time.sleep(interval_s)


def _restore_encryption_config(xray, original: dict) -> None:
    """Put the account's X-Ray encryption config back the way it was.

    The encryption config is ACCOUNT-global, not per-resource, so a check that flips it to
    Type=NONE must restore whatever was there (potentially a KMS key) or it silently
    reconfigures the whole account for every later check.
    """
    if original.get("Type") == "KMS" and original.get("KeyId"):
        xray.put_encryption_config(Type="KMS", KeyId=original["KeyId"])
    else:
        xray.put_encryption_config(Type="NONE")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """PutEncryptionConfig rejects an out-of-enum Type with ValidationException;
    a valid Type=NONE request is accepted and (eventually) reports Status=ACTIVE
    via GetEncryptionConfig."""
    xray = ctx.client("xray")

    original = xray.get_encryption_config()["EncryptionConfig"]
    ctx.on_cleanup(lambda: _restore_encryption_config(xray, original))

    bad_code, bad_message = _error(lambda: xray.put_encryption_config(Type="NOT_A_TYPE"))
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code}"
    assert bad_message == (
        "1 validation error detected: Value 'NOT_A_TYPE' at 'type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [KMS, NONE]"
    ), f"unexpected message: {bad_message!r}"

    resp = xray.put_encryption_config(Type="NONE")
    assert resp["EncryptionConfig"]["Type"] == "NONE"
    # PutEncryptionConfig is asynchronous: the config can enter UPDATING before it
    # settles on ACTIVE (a request that changes nothing can answer ACTIVE at once),
    # so the first answer may be either; the poll below requires ACTIVE.
    assert resp["EncryptionConfig"]["Status"] in ("UPDATING", "ACTIVE"), (
        f"unexpected initial status: {resp['EncryptionConfig']['Status']}"
    )

    result = _poll_until(
        lambda: xray.get_encryption_config(),
        lambda r: r["EncryptionConfig"]["Status"] == "ACTIVE",
        timeout_s=300,
        interval_s=10,
        description="X-Ray encryption config reaching Status=ACTIVE",
    )
    assert result["EncryptionConfig"]["Type"] == "NONE"
    assert result["EncryptionConfig"]["Status"] == "ACTIVE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
