"""batch-get-secret-value-binary-secret-returns-raw-bytes."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _digest(data: bytes) -> str:
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(data).hexdigest()[:16]


CHECK = "batch-get-secret-value-binary-secret-returns-raw-bytes"
GROUP = "data-plane"
SERVICES = ["secretsmanager"]

# Every byte value once, then a run that is invalid UTF-8 on its own: a target that stores
# or returns the blob through a text path (decode/encode, or base64 left un-decoded) cannot
# reproduce it.
_BLOB_V1 = bytes(range(256)) + b"\xff\xfe\x00\xc3\x28"
_BLOB_V2 = b"\x80\x81\x82" * 40 + b"\x00" * 16


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Non-UTF-8 SecretBinary comes back byte-identical via BatchGetSecretValue beside a string
    secret, each entry carrying only the field it was stored as; after a binary PutSecretValue
    both read paths serve the same new AWSCURRENT version.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-bgbin-")
    bin_name = f"{base}-bin"
    str_name = f"{base}-str"
    text = "sim2real-not-a-real-secret"

    bin_created = _create_secret(sm, ctx, bin_name, SecretBinary=_BLOB_V1)
    str_created = _create_secret(sm, ctx, str_name, SecretString=text)

    batch = sm.batch_get_secret_value(SecretIdList=[bin_created["ARN"], str_created["ARN"]])
    assert batch.get("Errors", []) == [], f"an all-success batch reported errors: {batch.get('Errors')}"
    entries = {e["Name"]: e for e in batch["SecretValues"]}
    assert set(entries) == {bin_name, str_name}, (
        f"the batch must return exactly the two requested secrets, got {sorted(entries)}"
    )

    b = entries[bin_name]
    assert "SecretString" not in b, (
        f"a binary secret's batch entry must not carry SecretString; entry keys {sorted(b)}"
    )
    got = b.get("SecretBinary")
    assert isinstance(got, bytes), f"SecretBinary must decode to bytes, got {type(got).__name__}"
    assert got == _BLOB_V1, (
        f"batch SecretBinary must be byte-identical to what was written: {len(got)} bytes "
        f"sha256 {_digest(got)} != {len(_BLOB_V1)} bytes sha256 {_digest(_BLOB_V1)}"
    )
    assert b["VersionId"] == bin_created["VersionId"], (
        "the batch entry must serve the version CreateSecret minted"
    )
    assert b["VersionStages"] == ["AWSCURRENT"], (
        f"the only version must be AWSCURRENT, got {b.get('VersionStages')!r}"
    )

    s = entries[str_name]
    assert "SecretBinary" not in s, (
        f"a string secret's batch entry must not carry SecretBinary; entry keys {sorted(s)}"
    )
    assert s.get("SecretString") == text, "the string secret must come back unchanged in the batch"

    put = sm.put_secret_value(SecretId=bin_name, SecretBinary=_BLOB_V2)
    single = sm.get_secret_value(SecretId=bin_name)
    assert single["VersionId"] == put["VersionId"], "GetSecretValue must serve the new version"
    assert single["SecretBinary"] == _BLOB_V2, (
        f"GetSecretValue after the binary put returned sha256 {_digest(single['SecretBinary'])}, "
        f"expected {_digest(_BLOB_V2)}"
    )

    again = sm.batch_get_secret_value(SecretIdList=[bin_name])
    assert again.get("Errors", []) == [], f"batch errors after the put: {again.get('Errors')}"
    [entry] = again["SecretValues"]
    assert entry["VersionId"] == put["VersionId"], (
        "BatchGetSecretValue must serve the same AWSCURRENT version GetSecretValue does"
    )
    assert entry["SecretBinary"] == _BLOB_V2, (
        f"batch SecretBinary after the put has sha256 {_digest(entry['SecretBinary'])}, "
        f"expected {_digest(_BLOB_V2)}"
    )

    previous = sm.get_secret_value(SecretId=bin_name, VersionStage="AWSPREVIOUS")
    assert previous["VersionId"] == bin_created["VersionId"], "the first version must be AWSPREVIOUS"
    assert previous["SecretBinary"] == _BLOB_V1, "the AWSPREVIOUS bytes must be unchanged by the put"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
