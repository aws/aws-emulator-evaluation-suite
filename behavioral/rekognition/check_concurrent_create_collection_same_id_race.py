"""concurrent-create-collection-same-id-race."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags

CHECK = "concurrent-create-collection-same-id-race"
GROUP = "concurrency"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers CreateCollection with the identical CollectionId: exactly one succeeds, the rest get ResourceAlreadyExistsException."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-race-")
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, collection_id))

    racer_count = 8

    def attempt(_):
        from botocore.exceptions import ClientError

        try:
            rek.create_collection(CollectionId=collection_id)
            return ("ok", None)
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with concurrent.futures.ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(attempt, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ResourceAlreadyExistsException" for _, (code, _msg) in failures), (
        f"expected every loser to see ResourceAlreadyExistsException, got: {failures}"
    )
    already_exists_message = f"The collection id: {collection_id} already exists"
    assert all(msg == already_exists_message for _, (_code, msg) in failures), (
        f"expected every loser to see {already_exists_message!r}, got: {failures}"
    )

    # the collection genuinely exists exactly once afterwards
    described = rek.describe_collection(CollectionId=collection_id)
    assert described["FaceCount"] == 0, f"expected an empty new collection, got {described['FaceCount']}"

    # tag it post-creation (not on the racing CreateCollection itself: passing Tags there
    # changes the losers' error to InvalidParameterException instead of
    # ResourceAlreadyExistsException on real AWS, which would test tagging, not the race)
    rek.tag_resource(
        ResourceArn=described["CollectionARN"], Tags={"env": "sim2real", "owner": "behavioral"}
    )

    # the cleanup below deletes this collection; prove that delete is real rather than a
    # no-op that merely raised no error — an independent read must 404, and a further
    # mutation on the now-dead id must fail with the same specific not-found code.
    rek.delete_collection(CollectionId=collection_id)
    not_found_message = f"Collection:{collection_id} not found!"
    describe_code, describe_message = _client_error(lambda: rek.describe_collection(CollectionId=collection_id))
    assert describe_code == "ResourceNotFoundException", (
        f"expected describe of a deleted collection to 404, got {describe_code!r}"
    )
    assert describe_message == not_found_message, (
        f"expected describe of a deleted collection to say {not_found_message!r}, got {describe_message!r}"
    )
    redelete_code, redelete_message = _client_error(lambda: rek.delete_collection(CollectionId=collection_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected delete of an already-deleted collection to 404, got {redelete_code!r}"
    )
    assert redelete_message == not_found_message, (
        f"expected delete of an already-deleted collection to say {not_found_message!r}, got {redelete_message!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
