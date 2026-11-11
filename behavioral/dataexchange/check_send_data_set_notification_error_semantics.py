"""send-data-set-notification-error-semantics."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-data-set-notification-error-semantics"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendDataSetNotification fails with ValidationException "Data set not configured for AWS Marketplace Data
    Product." for an owned unpublished data set, and with ResourceNotFoundException "The requested resource
    was not found." for a never-created DataSetId."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    code_not_configured, code_not_configured_message = _error(
        lambda: dx.send_data_set_notification(
            DataSetId=dataset_id,
            Type="DATA_UPDATE",
            Details={"DataUpdate": {"DataUpdatedAt": now_iso}},
        )
    )
    assert code_not_configured == "ValidationException", code_not_configured
    assert code_not_configured_message == "Data set not configured for AWS Marketplace Data Product.", (
        f"expected the exact not-configured-for-marketplace message, got {code_not_configured_message!r}"
    )

    nonexistent_dataset_id = "c" * 38
    code_missing, code_missing_message = _error(
        lambda: dx.send_data_set_notification(
            DataSetId=nonexistent_dataset_id,
            Type="DATA_UPDATE",
            Details={"DataUpdate": {"DataUpdatedAt": now_iso}},
        )
    )
    assert code_missing == "ResourceNotFoundException", code_missing
    assert code_missing_message == "The requested resource was not found.", (
        f"expected the exact refusal message, got {code_missing_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

