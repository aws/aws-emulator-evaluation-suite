"""op-encrypt-oversized-plaintext-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-encrypt-oversized-plaintext-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Symmetric Encrypt accepts exactly 4096 plaintext bytes and must reject 4097."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-op-bigpt-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-op-encrypt-oversized-plaintext"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    at_limit = kms.encrypt(KeyId=key_id, Plaintext=b"x" * 4096)
    assert at_limit["CiphertextBlob"], "4096 bytes is exactly at the documented limit"

    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"x" * 4097))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: "
        "Member must have length less than or equal to 4096"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
