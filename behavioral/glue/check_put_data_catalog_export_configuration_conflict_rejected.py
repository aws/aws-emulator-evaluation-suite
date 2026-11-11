"""put-data-catalog-export-configuration-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-data-catalog-export-configuration-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]

#: How long the restore retries a ConflictException while a just-applied setting settles.
_RESTORE_S = 120.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDataCatalogExportConfiguration attempting to change the encryption settings of an
    export configuration that is already ENABLED with a different, incompatible encryption
    mode raises ConflictException instead of silently switching encryption schemes."""
    glue = ctx.client("glue")
    kms = ctx.client("kms")

    original = _get_original_export_configuration(glue)

    def _restore():
        if original is None:
            kwargs = {"ExportSetting": "DISABLED"}
        else:
            kwargs = {"ExportSetting": original["ExportSetting"]}
            if "EncryptionConfiguration" in original:
                kwargs["EncryptionConfiguration"] = original["EncryptionConfiguration"]
        # A setting still being applied refuses with ConflictException; anything else raises.
        deadline = time.monotonic() + _RESTORE_S
        while True:
            try:
                glue.put_data_catalog_export_configuration(**kwargs)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_restore)

    key_arn = kms.create_key(Description="sim2real glue export config test key")[
        "KeyMetadata"
    ]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    try:
        glue.put_data_catalog_export_configuration(
            ExportSetting="ENABLED", EncryptionConfiguration={"SseAlgorithm": "AES256"}
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "AccessDeniedException":
            raise AssertionError(
                "caller lacks permission to enable Glue Data Catalog export to S3 Tables "
                "(glue:PutDataCatalogExportConfiguration / s3tables:CreateTable); cannot "
                "exercise the conflicting-reconfiguration path without it"
            )
        if code == "ConflictException" and "table bucket" in message.lower():
            # A residual account-singleton S3 Tables bucket named "aws-catalog" is in a
            # state this attempt cannot reconcile. The check never created that bucket, so
            # it reports the unmet precondition and never deletes it.
            raise AssertionError(
                "a pre-existing S3 Tables bucket named 'aws-catalog' in this account "
                "is in a state (encryption/ownership) that PutDataCatalogExport"
                "Configuration cannot reconcile, so the ENABLED baseline this check "
                f"needs is unreachable: {e}"
            )
        else:
            raise

    # Negative: immediately switching to an incompatible (SSE-KMS) encryption mode while
    # the export configuration is still transitioning from the just-applied SSE-S3 setting
    # must be rejected, not silently applied.
    code, message = _error_code(
        lambda: glue.put_data_catalog_export_configuration(
            ExportSetting="ENABLED",
            EncryptionConfiguration={"SseAlgorithm": "aws:kms", "KmsKeyArn": key_arn},
        )
    )
    assert code == "ConflictException", f"expected ConflictException switching AES256->KMS while ENABLED, got {code!r}"
    # AWS returns the JSON error body as this refusal's message.
    expected = (
        '{"Message":"The existing table bucket aws-catalog uses a different encryption '
        'configuration than the request."}'
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the encryption mode is still the original SSE-S3 setting, not KMS.
    current = glue.get_data_catalog_export_configuration()
    got_alg = current["EncryptionConfiguration"]["SseAlgorithm"]
    assert got_alg == "AES256", f"expected encryption to remain AES256 after the rejected switch, got {got_alg!r}"

    # Positive control (same file): disabling and then re-enabling with the SAME
    # (now-current) encryption mode succeeds normally.
    glue.put_data_catalog_export_configuration(ExportSetting="DISABLED")
    glue.put_data_catalog_export_configuration(
        ExportSetting="ENABLED", EncryptionConfiguration={"SseAlgorithm": "AES256"}
    )
    after_control = glue.get_data_catalog_export_configuration()
    got_setting = after_control["ExportSetting"]
    assert got_setting == "ENABLED", f"expected ENABLED after re-enabling with the original encryption, got {got_setting!r}"


def _error_code(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _get_original_export_configuration(glue):
    try:
        return glue.get_data_catalog_export_configuration()
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityNotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
