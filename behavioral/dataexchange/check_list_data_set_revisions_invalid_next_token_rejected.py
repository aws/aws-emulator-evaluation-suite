"""list-data-set-revisions-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-data-set-revisions-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDataSetRevisions rejects a malformed pagination token with
    ValidationException, while the same call with no token succeeds."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)

    # Positive control: an unpaginated call against a real data set succeeds.
    baseline = dx.list_data_set_revisions(DataSetId=dataset_id, MaxResults=10)
    assert "Revisions" in baseline, f"expected a Revisions list in the baseline response, got {baseline!r}"

    code, message = _error(
        lambda: dx.list_data_set_revisions(DataSetId=dataset_id, NextToken="not-a-real-token!!")
    )
    assert code == "ValidationException", f"expected ValidationException for a malformed NextToken, got {code!r}"
    assert message == "Invalid NextToken. Account Id does not match Caller's Account Id.", f"expected the exact refusal message, got {message!r}"


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
    ds = dx.create_data_set(AssetType="S3_SNAPSHOT", Description="sim2real check", Name=name)
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
