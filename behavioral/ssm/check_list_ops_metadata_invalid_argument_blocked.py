"""list-ops-metadata-invalid-argument-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-ops-metadata-invalid-argument-blocked"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOpsMetadata filtered by the supported ResourceId key returns an empty list, while an unsupported
    filter Key fails with OpsMetadataInvalidArgumentException and the exact message."""
    ssm = ctx.client("ssm")
    resource_id = ctx.unique_name("sim2real-opsmeta-filter-")

    # Positive control: filtering by the documented, supported "ResourceId" key succeeds
    # (returns an empty list for a resource that has no OpsMetadata object -- it does not
    # raise).
    found = ssm.list_ops_metadata(
        Filters=[{"Key": "ResourceId", "Values": [resource_id]}]
    )["OpsMetadataList"]
    assert found == [], f"expected no OpsMetadata for an unused ResourceId, got {found!r}"

    # Negative: an unsupported filter key.
    err = _error(
        lambda: ssm.list_ops_metadata(
            Filters=[{"Key": "TotallyBogusFilterKey", "Values": ["whatever"]}]
        )
    )
    assert err["Code"] == "OpsMetadataInvalidArgumentException", (
        f"expected OpsMetadataInvalidArgumentException for an unsupported filter key, got {err!r}"
    )
    expected_message = (
        "The following OpsMetadataFilter key is not valid: TotallyBogusFilterKey. "
        "Valid filter keys include: [ResourceId, provisioned-by, application-type]."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a filter key real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

