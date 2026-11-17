"""catalog-encryption-without-a-key-resolves-to-the-aws-managed-glue-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-encryption-without-a-key-resolves-to-the-aws-managed-glue-key"
GROUP = "representation"
SERVICES = ["glue", "kms"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:glue-catalog-encryption",
)
def run(ctx) -> None:
    """Enabling catalog SSE-KMS with no KMS key resolves to the AWS managed key alias/aws/glue,
    which decrypts a table created right after, and the original encryption settings are restored.

    Reference: https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html
    """
    glue = ctx.client("glue")
    kms = ctx.client("kms")

    original = glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"]
    ctx.on_cleanup(lambda: glue.put_data_catalog_encryption_settings(DataCatalogEncryptionSettings=original))

    new_settings = dict(original)
    new_settings["EncryptionAtRest"] = {"CatalogEncryptionMode": "SSE-KMS"}
    glue.put_data_catalog_encryption_settings(DataCatalogEncryptionSettings=new_settings)

    resolved = _poll_until(
        lambda: glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"]["EncryptionAtRest"],
        lambda enc: enc.get("CatalogEncryptionMode") == "SSE-KMS",
        timeout_s=30,
        interval_s=2,
    )
    assert resolved["CatalogEncryptionMode"] == "SSE-KMS", (
        f"catalog encryption mode is {resolved.get('CatalogEncryptionMode')!r} after enabling "
        "SSE-KMS with no key, want 'SSE-KMS'"
    )

    # Our own PutDataCatalogEncryptionSettings is the first use that needs this key; describing
    # it now confirms the default it resolved to, rather than assuming it pre-exists.
    managed_key = kms.describe_key(KeyId="alias/aws/glue")["KeyMetadata"]
    assert managed_key["KeyManager"] == "AWS", (
        f"expected alias/aws/glue to be an AWS-managed key, got KeyManager={managed_key['KeyManager']!r}"
    )
    key_ref = resolved.get("SseAwsKmsKeyId", "")
    assert key_ref in (managed_key["KeyId"], managed_key["Arn"], "alias/aws/glue"), (
        f"catalog resolved SseAwsKmsKeyId to {key_ref!r}, which names neither alias/aws/glue's "
        f"KeyId ({managed_key['KeyId']!r}) nor its Arn ({managed_key['Arn']!r}) nor the alias itself"
    )

    db_name = ctx.unique_name("sim2real_behav_glue_dqkey_db_")
    table_name = ctx.unique_name("sim2real_behav_glue_dqkey_tbl_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

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
    ctx.on_cleanup(lambda: _delete_table_idempotent(glue, db_name, table_name))

    fetched = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert fetched["Name"] == table_name, (
        f"GetTable returned name {fetched.get('Name')!r} under the AWS-managed-key catalog "
        f"setting, want {table_name!r}"
    )
    assert fetched["DatabaseName"] == db_name, (
        f"GetTable returned database {fetched.get('DatabaseName')!r}, want {db_name!r}"
    )

    glue.put_data_catalog_encryption_settings(DataCatalogEncryptionSettings=original)
    restored = _poll_until(
        lambda: glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"],
        lambda enc: enc.get("EncryptionAtRest", {}).get("CatalogEncryptionMode")
        == original.get("EncryptionAtRest", {}).get("CatalogEncryptionMode"),
        timeout_s=30,
        interval_s=2,
    )
    assert restored.get("EncryptionAtRest", {}).get("CatalogEncryptionMode") == original.get(
        "EncryptionAtRest", {}
    ).get("CatalogEncryptionMode"), (
        f"catalog encryption did not restore to the original mode "
        f"{original.get('EncryptionAtRest', {}).get('CatalogEncryptionMode')!r}, got "
        f"{restored.get('EncryptionAtRest', {}).get('CatalogEncryptionMode')!r}"
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


def _delete_table_idempotent(glue, db_name, table_name):
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
