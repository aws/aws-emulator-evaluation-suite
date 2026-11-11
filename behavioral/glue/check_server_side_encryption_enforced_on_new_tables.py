"""server-side-encryption-enforced-on-new-tables."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "server-side-encryption-enforced-on-new-tables"
GROUP = "server-side"
SERVICES = ["glue"]

_PROPAGATION_BUDGET_S = 120.0
_POLL_S = 3.0


def _filled(template, message):
    """`template` with its {rid} slots filled, in order, from the request ids `message` carries:
    the per-call part each wrapped service appends."""
    rids = iter(re.findall(r"Request ID: ([0-9a-f-]+);", message or ""))
    return re.sub(r"\{rid\}", lambda m: next(rids, "?"), template)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:glue-catalog-encryption")
def run(ctx) -> None:
    """With catalog SSE-KMS enabled, a new table is decrypted through the CMK: disabling the key makes
    GetTable fail with GlueEncryptionException, and re-enabling it restores the original metadata.
    """
    glue = ctx.client("glue")
    kms = ctx.client("kms")

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-glue-catalog-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "glue-catalog-sse-kms"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    original = glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"]
    ctx.on_cleanup(lambda: glue.put_data_catalog_encryption_settings(DataCatalogEncryptionSettings=original))

    glue.put_data_catalog_encryption_settings(
        DataCatalogEncryptionSettings={
            "EncryptionAtRest": {"CatalogEncryptionMode": "SSE-KMS", "SseAwsKmsKeyId": key_id},
        }
    )

    reread = _poll_until(
        lambda: glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"][
            "EncryptionAtRest"
        ],
        lambda enc: enc.get("CatalogEncryptionMode") == "SSE-KMS",
        timeout_s=30,
        interval_s=2,
    )
    assert reread["CatalogEncryptionMode"] == "SSE-KMS", (
        f"catalog encryption mode is {reread.get('CatalogEncryptionMode')!r} after "
        "PutDataCatalogEncryptionSettings, want 'SSE-KMS'"
    )
    assert reread["SseAwsKmsKeyId"] == key_id, (
        f"catalog is keyed to {reread.get('SseAwsKmsKeyId')!r}, want the key this check created "
        f"({key_id!r})"
    )

    db_name = ctx.unique_name("sim2real_glue_db_")
    table_name = ctx.unique_name("sim2real_glue_tbl_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    # No encryption parameter: the table is protected by the catalog-wide setting.
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Location": f"s3://{db_name}-nonexistent/data/",
                "Columns": [{"Name": "id", "Type": "bigint"}],
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    fetched = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert fetched["Name"] == table_name, (
        f"GetTable returned name {fetched.get('Name')!r} while the CMK is enabled, want {table_name!r}"
    )
    assert fetched["DatabaseName"] == db_name, (
        f"GetTable returned database {fetched.get('DatabaseName')!r} while the CMK is enabled, "
        f"want {db_name!r}"
    )

    # Poll the read outcome: no API reports when a key-state change reaches Glue's decrypt path.
    kms.disable_key(KeyId=key_id)
    key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert key_meta["KeyState"] == "Disabled", (
        "DisableKey returned but DescribeKey does not report the key as Disabled"
    )

    denied = _poll_until(
        lambda: _client_error(lambda: glue.get_table(DatabaseName=db_name, Name=table_name)),
        lambda e: e is not None,
        timeout_s=_PROPAGATION_BUDGET_S,
        interval_s=_POLL_S,
    )
    assert denied is not None, (
        f"GetTable still succeeded {_PROPAGATION_BUDGET_S:.0f}s after the catalog's CMK was "
        "disabled -- the table's metadata is not actually encrypted with that key, so catalog "
        "SSE-KMS is a stored flag rather than cryptography"
    )
    code = denied.response.get("Error", {}).get("Code")
    assert code == "GlueEncryptionException", (
        f"expected GlueEncryptionException on a catalog read whose CMK is disabled, got {code!r} "
        f"({denied.response.get('Error', {}).get('Message')!r}) -- Glue's own model reserves "
        "GlueEncryptionException for 'an encryption operation failed', so anything else means the "
        "read never actually depended on the key"
    )
    # GlueEncryptionException relays the KMS DisabledException with its per-request id.
    message = denied.response.get("Error", {}).get("Message", "")
    expected = _filled(
        f"{key_meta['Arn']} is disabled. (Service: AWSKMS; Status Code: 400; "
        "Error Code: DisabledException; Request ID: {rid}; Proxy: null)",
        message,
    )
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    kms.enable_key(KeyId=key_id)
    restored = _poll_until(
        lambda: _client_error(lambda: glue.get_table(DatabaseName=db_name, Name=table_name)),
        lambda e: e is None,
        timeout_s=_PROPAGATION_BUDGET_S,
        interval_s=_POLL_S,
    )
    assert restored is None, (
        f"GetTable still failed ({restored}) {_PROPAGATION_BUDGET_S:.0f}s after the CMK was re-enabled"
    )
    final = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert final["Name"] == table_name, (
        f"the table did not survive the disable/enable cycle: name is {final.get('Name')!r}, "
        f"want {table_name!r}"
    )
    assert final["DatabaseName"] == db_name, (
        f"the table did not survive the disable/enable cycle: database is "
        f"{final.get('DatabaseName')!r}, want {db_name!r}"
    )
    assert final["StorageDescriptor"]["Columns"] == fetched["StorageDescriptor"]["Columns"], (
        "the table's column definitions changed across the CMK disable/enable cycle -- the "
        "metadata was replaced rather than merely made unreadable"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"condition not met within {timeout_s:.0f}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _retire_key(kms, key_id):
    """Re-enable then schedule deletion, so a mid-check failure never leaves a disabled key."""
    try:
        kms.enable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
