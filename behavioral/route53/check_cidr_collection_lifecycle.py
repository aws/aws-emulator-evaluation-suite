"""cidr-collection-lifecycle."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cidr-collection-lifecycle"
GROUP = 'cidr-collection'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _delete_if_present(fn):
    """Teardown delete that tolerates the collection already being gone (the check deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchCidrCollectionException":
            raise


def _current_version(r53, cc_id):
    listed = r53.list_cidr_collections()
    match = [c for c in listed["CidrCollections"] if c["Id"] == cc_id]
    assert len(match) == 1, f"expected exactly one collection {cc_id!r} in {listed}"
    return match[0]["Version"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeCidrCollection increments Version and adds a visible CIDR block; a stale Version is
    rejected with no effect; retrying with the current Version then succeeds; deleting the
    collection makes it unreachable by an independent read and by further mutation."""
    r53 = ctx.client("route53")
    resp = r53.create_cidr_collection(Name=ctx.unique_name("sim2real-behav-cidr"), CallerReference=_caller_reference())
    cc_id = resp["Collection"]["Id"]
    ctx.on_cleanup(lambda i=cc_id: _delete_if_present(lambda: r53.delete_cidr_collection(Id=i)))

    listed0 = r53.list_cidr_collections()
    match = [c for c in listed0["CidrCollections"] if c["Id"] == cc_id]
    assert len(match) == 1, f"expected exactly one collection {cc_id!r} in {listed0}"

    stale_version = match[0]["Version"]

    r53.change_cidr_collection(
        Id=cc_id,
        Changes=[{"LocationName": "loc-a", "Action": "PUT", "CidrList": ["10.0.0.0/24"]}],
    )

    blocks = r53.list_cidr_blocks(CollectionId=cc_id)
    assert any(b["CidrBlock"] == "10.0.0.0/24" for b in blocks["CidrBlocks"]), (
        f"expected 10.0.0.0/24 among {blocks['CidrBlocks']}"
    )

    # the PUT above already consumed `stale_version`; reusing it now must be rejected
    code, message = _error_code(
        lambda: r53.change_cidr_collection(
            Id=cc_id,
            Changes=[{"LocationName": "loc-b", "Action": "PUT", "CidrList": ["10.0.1.0/24"]}],
            CollectionVersion=stale_version,
        )
    )
    assert code == "CidrCollectionVersionMismatchException", (
        f"expected CidrCollectionVersionMismatchException, got {code}"
    )
    # AWS returns this refusal with an empty message.
    assert message == "", f"expected an empty message, got {message!r}"

    # effect absent: the rejected change must not have added loc-b's block
    blocks_after_reject = r53.list_cidr_blocks(CollectionId=cc_id)
    assert not any(b["CidrBlock"] == "10.0.1.0/24" for b in blocks_after_reject["CidrBlocks"]), (
        f"expected no 10.0.1.0/24 after rejected change, saw {blocks_after_reject['CidrBlocks']}"
    )

    # restore: the identical change, now carrying the current Version, succeeds
    current_version = _current_version(r53, cc_id)
    r53.change_cidr_collection(
        Id=cc_id,
        Changes=[{"LocationName": "loc-b", "Action": "PUT", "CidrList": ["10.0.1.0/24"]}],
        CollectionVersion=current_version,
    )
    blocks_after_restore = r53.list_cidr_blocks(CollectionId=cc_id)
    assert any(b["CidrBlock"] == "10.0.1.0/24" for b in blocks_after_restore["CidrBlocks"]), (
        f"expected 10.0.1.0/24 among {blocks_after_restore['CidrBlocks']}"
    )

    r53.change_cidr_collection(
        Id=cc_id,
        Changes=[
            {"LocationName": "loc-a", "Action": "DELETE_IF_EXISTS", "CidrList": ["10.0.0.0/24"]},
            {"LocationName": "loc-b", "Action": "DELETE_IF_EXISTS", "CidrList": ["10.0.1.0/24"]},
        ],
    )
    r53.delete_cidr_collection(Id=cc_id)

    # deletes prove gone and unusable: an independent read no longer lists it, and a mutation
    # against the dead id fails with the specific not-found code
    listed_after_delete = r53.list_cidr_collections()
    assert not any(c["Id"] == cc_id for c in listed_after_delete["CidrCollections"]), (
        f"expected {cc_id!r} absent after delete, saw {listed_after_delete['CidrCollections']}"
    )
    dead_code, dead_message = _error_code(
        lambda: r53.change_cidr_collection(
            Id=cc_id,
            Changes=[{"LocationName": "loc-a", "Action": "DELETE_IF_EXISTS", "CidrList": ["10.0.0.0/24"]}],
        )
    )
    assert dead_code == "NoSuchCidrCollectionException", (
        f"expected NoSuchCidrCollectionException on a deleted collection, got {dead_code}"
    )
    # AWS returns this refusal with an empty message.
    assert dead_message == "", f"expected an empty message, got {dead_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
