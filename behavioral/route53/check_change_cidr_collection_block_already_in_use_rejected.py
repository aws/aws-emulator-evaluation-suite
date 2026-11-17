"""change-cidr-collection-block-already-in-use-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-cidr-collection-block-already-in-use-rejected"
GROUP = "cidr-collection"
SERVICES = ["route53"]

_CIDR = "192.0.2.0/24"
_OTHER_CIDR = "198.51.100.0/24"


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _current_version(r53, collection_id: str) -> int:
    for c in r53.list_cidr_collections()["CidrCollections"]:
        if c["Id"] == collection_id:
            return c["Version"]
    raise AssertionError(f"collection {collection_id!r} missing from ListCidrCollections")


def _blocks_at(r53, collection_id: str, location_name: str) -> set[str]:
    return {
        b["CidrBlock"]
        for b in r53.list_cidr_blocks(CollectionId=collection_id, LocationName=location_name)[
            "CidrBlocks"
        ]
    }


def _empty_and_delete_collection(r53, collection_id: str) -> None:
    """Remove every CIDR block from every location, then delete the (now-empty) collection."""
    try:
        locations = r53.list_cidr_locations(CollectionId=collection_id)["CidrLocations"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchCidrCollectionException":
            return
        raise
    changes = []
    for loc in locations:
        blocks = sorted(_blocks_at(r53, collection_id, loc["LocationName"]))
        if blocks:
            changes.append(
                {"LocationName": loc["LocationName"], "Action": "DELETE_IF_EXISTS", "CidrList": blocks}
            )
    if changes:
        r53.change_cidr_collection(
            Id=collection_id,
            CollectionVersion=_current_version(r53, collection_id),
            Changes=changes,
        )
    try:
        r53.delete_cidr_collection(Id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCidrCollectionException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeCidrCollection refuses PUTting a CIDR block into a location when another location
    in the same collection already holds it, and adds nothing, while a disjoint block succeeds.
    """
    r53 = ctx.client("route53")
    collection_name = ctx.unique_name("sim2realbehavcidr")
    created = r53.create_cidr_collection(
        CallerReference=ctx.unique_name("sim2real-behav-cc-"), Name=collection_name
    )
    collection_id = created["Collection"]["Id"]
    ctx.on_cleanup(lambda i=collection_id: _empty_and_delete_collection(r53, i))

    version = _current_version(r53, collection_id)
    r53.change_cidr_collection(
        Id=collection_id,
        CollectionVersion=version,
        Changes=[{"LocationName": "loc-a", "Action": "PUT", "CidrList": [_CIDR]}],
    )

    # Positive control: the block really landed under loc-a.
    assert _blocks_at(r53, collection_id, "loc-a") == {_CIDR}, _blocks_at(r53, collection_id, "loc-a")

    # Break: PUT the SAME block into a different location in the same collection.
    version = _current_version(r53, collection_id)
    err = _error(
        lambda: r53.change_cidr_collection(
            Id=collection_id,
            CollectionVersion=version,
            Changes=[{"LocationName": "loc-b", "Action": "PUT", "CidrList": [_CIDR]}],
        )
    )
    assert err.get("Code") == "CidrBlockInUseException", (
        f"expected CidrBlockInUseException reusing {_CIDR} under a second location, got {err!r}"
    )
    assert err.get("Message") == "", err

    # The refused change added nothing under loc-b, and loc-a is unaffected.
    assert _blocks_at(r53, collection_id, "loc-b") == set(), _blocks_at(r53, collection_id, "loc-b")
    assert _blocks_at(r53, collection_id, "loc-a") == {_CIDR}, _blocks_at(r53, collection_id, "loc-a")

    # The legal neighbour: a disjoint block into the same new location succeeds.
    version = _current_version(r53, collection_id)
    r53.change_cidr_collection(
        Id=collection_id,
        CollectionVersion=version,
        Changes=[{"LocationName": "loc-b", "Action": "PUT", "CidrList": [_OTHER_CIDR]}],
    )
    assert _blocks_at(r53, collection_id, "loc-b") == {_OTHER_CIDR}, _blocks_at(r53, collection_id, "loc-b")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
