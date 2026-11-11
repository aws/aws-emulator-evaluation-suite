"""list-collections-reflects-created-and-deleted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-collections-reflects-created-and-deleted"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCollections includes newly created collections and stops including them after delete."""
    rek = ctx.client("rekognition")
    id_a = ctx.unique_name("sim2real-rek-list-a-")
    id_b = ctx.unique_name("sim2real-rek-list-b-")
    resource_tags = {"env": "sim2real", "owner": "behavioral"}

    rek.create_collection(CollectionId=id_a, Tags=resource_tags)
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, id_a))
    rek.create_collection(CollectionId=id_b, Tags=resource_tags)
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, id_b))

    all_ids = _list_all_collection_ids(rek)
    assert id_a in all_ids, f"expected {id_a} in ListCollections after create, got {sorted(all_ids)}"
    assert id_b in all_ids, f"expected {id_b} in ListCollections after create, got {sorted(all_ids)}"

    rek.delete_collection(CollectionId=id_a)
    all_ids_after = _list_all_collection_ids(rek)
    assert id_a not in all_ids_after, (
        f"expected {id_a} absent from ListCollections after delete, got {sorted(all_ids_after)}"
    )
    assert id_b in all_ids_after, f"expected {id_b} still in ListCollections, got {sorted(all_ids_after)}"

    code, message = _client_error(lambda: rek.delete_collection(CollectionId=id_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException re-deleting {id_a}, got {code}"
    assert message == f"Collection:{id_a} not found!", f"re-deleting {id_a} returned message {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_collection_ignore_missing(rek, collection_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rek.delete_collection(CollectionId=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_collection_ids(rek) -> set:
    ids: set = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = rek.list_collections(**kwargs)
        ids.update(resp.get("CollectionIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
