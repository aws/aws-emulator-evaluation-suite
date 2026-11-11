"""list-ops-metadata-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-ops-metadata-invalid-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOpsMetadata filtered on the supported ResourceId key answers with no match for the check's resource,
    while an unsupported filter key fails with OpsMetadataInvalidArgumentException and the exact message."""
    ssm = ctx.client("ssm")
    resource_id = ctx.unique_name("sim2real-ssm-opsmeta-")

    # positive control: filtering on the supported "ResourceId" key is accepted (no error),
    # even though nothing matches it
    good = ssm.list_ops_metadata(Filters=[{"Key": "ResourceId", "Values": [resource_id]}])
    assert "OpsMetadataList" in good, f"expected 'OpsMetadataList' key in response, got keys={sorted(good.keys())}"
    matches = [item for item in good["OpsMetadataList"] if item["ResourceId"] == resource_id]
    assert not matches, f"expected no OpsMetadataList item for freshly generated {resource_id!r}, got {matches}"

    # break exactly one thing: an unsupported filter key
    err = _error(
        lambda: ssm.list_ops_metadata(Filters=[{"Key": "NotASupportedFilterKey", "Values": ["x"]}])
    )
    assert err["Code"] == "OpsMetadataInvalidArgumentException", (
        f"expected OpsMetadataInvalidArgumentException for an unsupported filter key, got {err!r}"
    )
    expected_message = (
        "The following OpsMetadataFilter key is not valid: NotASupportedFilterKey. "
        "Valid filter keys include: [ResourceId, provisioned-by, application-type]."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a filter key real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected the unsupported filter key to be rejected, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
