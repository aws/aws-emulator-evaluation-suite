"""dataset-lifecycle-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-lifecycle-create-get-delete"
GROUP = "lifecycle"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSet -> GetDataSet reflects fields; DeleteDataSet removes it for good: an
    independent read 404s, a mutation on the dead id also fails, and it drops out of
    ListDataSets."""
    dx = ctx.client("dataexchange")
    name = ctx.unique_name("sim2real-dx-ds-")
    created = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real behavioral fidelity check dataset",
        Name=name,
    )
    dataset_id = created["Id"]
    assert created["Origin"] == "OWNED", f"expected Origin 'OWNED' on a self-created data set, got {created['Origin']!r}"
    assert created["Name"] == name, f"expected CreateDataSet to echo Name {name!r}, got {created['Name']!r}"

    got = dx.get_data_set(DataSetId=dataset_id)
    assert got["Id"] == dataset_id, f"expected GetDataSet Id {dataset_id!r}, got {got['Id']!r}"
    assert got["Name"] == name, f"expected GetDataSet Name {name!r}, got {got['Name']!r}"
    assert got["AssetType"] == "S3_SNAPSHOT", f"expected GetDataSet AssetType 'S3_SNAPSHOT', got {got['AssetType']!r}"
    assert got["Origin"] == "OWNED", f"expected GetDataSet Origin 'OWNED', got {got['Origin']!r}"

    listed_before = {d["Id"] for d in dx.list_data_sets()["DataSets"]}
    assert dataset_id in listed_before, f"expected {dataset_id!r} in ListDataSets before delete, saw {listed_before!r}"

    dx.delete_data_set(DataSetId=dataset_id)

    get_code, get_message = _error(lambda: dx.get_data_set(DataSetId=dataset_id))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetDataSet on the deleted id to fail with 'ResourceNotFoundException', got {get_code!r}"
    )
    assert get_message == "The requested resource was not found.", f"expected the exact refusal message, got {get_message!r}"

    update_code, update_message = _error(lambda: dx.update_data_set(DataSetId=dataset_id, Name="sim2real-dx-ds-dead"))
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateDataSet on the deleted id to fail with 'ResourceNotFoundException', got {update_code!r}"
    )
    assert update_message == "The requested resource was not found.", f"expected the exact refusal message, got {update_message!r}"

    listed_after = {d["Id"] for d in dx.list_data_sets()["DataSets"]}
    assert dataset_id not in listed_after, f"expected {dataset_id!r} gone from ListDataSets after delete, saw {listed_after!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
