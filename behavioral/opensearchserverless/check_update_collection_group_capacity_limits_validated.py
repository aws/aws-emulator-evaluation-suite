"""update-collection-group-capacity-limits-validated."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-collection-group-capacity-limits-validated"
GROUP = "concurrency"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCollectionGroup rejects an inverted min>max capacity window; a valid update persists."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-cg-")

    created = client.create_collection_group(
        name=name,
        standbyReplicas="ENABLED",
        generation="NEXTGEN",
        capacityLimits={
            "minIndexingCapacityInOCU": 0,
            "maxIndexingCapacityInOCU": 16,
            "minSearchCapacityInOCU": 0,
            "maxSearchCapacityInOCU": 16,
        },
        tags=[{"key": "sim2real", "value": name}],
    )["createCollectionGroupDetail"]
    group_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_collection_group(id=group_id))

    # Overly-permissive boundary: an inverted min>max capacity window must be rejected.
    code, message = _error(
        lambda: client.update_collection_group(
            id=group_id,
            capacityLimits={
                "minIndexingCapacityInOCU": 32,
                "maxIndexingCapacityInOCU": 16,
                "minSearchCapacityInOCU": 0,
                "maxSearchCapacityInOCU": 16,
            },
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an inverted min>max capacity window, got {code!r}"
    )
    expected_message = (
        "Invalid capacity range: minIndexingCapacityInOCU (32.0) exceeds maxIndexingCapacityInOCU (16.0)"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: the rejected update never changed the persisted limits.
    got = client.batch_get_collection_group(ids=[group_id])["collectionGroupDetails"][0]
    assert got["capacityLimits"]["maxIndexingCapacityInOCU"] == 16, (
        f'expected maxIndexingCapacityInOCU to remain 16 after the rejected update, '
        f'got {got["capacityLimits"]["maxIndexingCapacityInOCU"]!r}'
    )
    assert got["capacityLimits"]["minIndexingCapacityInOCU"] == 0, (
        f'expected minIndexingCapacityInOCU to remain 0 after the rejected update, '
        f'got {got["capacityLimits"]["minIndexingCapacityInOCU"]!r}'
    )

    # Positive control: a valid capacity update is accepted and actually persists.
    updated = client.update_collection_group(
        id=group_id,
        description="capacity-raised",
        capacityLimits={
            "minIndexingCapacityInOCU": 0,
            "maxIndexingCapacityInOCU": 32,
            "minSearchCapacityInOCU": 0,
            "maxSearchCapacityInOCU": 32,
        },
    )["updateCollectionGroupDetail"]
    assert updated["capacityLimits"]["maxIndexingCapacityInOCU"] == 32, (
        f'expected the accepted update\'s own response to report maxIndexingCapacityInOCU=32, '
        f'got {updated["capacityLimits"]["maxIndexingCapacityInOCU"]!r}'
    )
    assert updated["description"] == "capacity-raised", (
        f'expected the accepted update\'s own response to report description="capacity-raised", '
        f'got {updated["description"]!r}'
    )

    got2 = client.batch_get_collection_group(ids=[group_id])["collectionGroupDetails"][0]
    assert got2["capacityLimits"]["maxIndexingCapacityInOCU"] == 32, (
        f'expected the independently-read maxIndexingCapacityInOCU to persist as 32, '
        f'got {got2["capacityLimits"]["maxIndexingCapacityInOCU"]!r}'
    )
    assert got2["description"] == "capacity-raised", (
        f'expected the independently-read description to persist as "capacity-raised", '
        f'got {got2["description"]!r}'
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
