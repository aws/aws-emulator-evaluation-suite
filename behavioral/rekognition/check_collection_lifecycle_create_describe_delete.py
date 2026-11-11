"""collection-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "collection-lifecycle-create-describe-delete"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCollection -> DescribeCollection reflects it -> DeleteCollection -> DescribeCollection 404s."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-coll-")

    created = rek.create_collection(
        CollectionId=collection_id, Tags={"sim2real": "collection-lifecycle-create-describe-delete"}
    )
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, collection_id))
    assert created["StatusCode"] == 200, f"create_collection status: {created['StatusCode']}"
    assert created["CollectionArn"].endswith(collection_id), created["CollectionArn"]
    face_model_version = created["FaceModelVersion"]
    assert face_model_version, "create_collection returned no FaceModelVersion"

    # CreateCollection is eventually consistent with DescribeCollection: a read right after the
    # create can still answer not-found, so this waits a bounded time for the collection to resolve.
    described = _describe_when_visible(rek, collection_id, timeout_s=30.0)
    fixed_created_arn = created["CollectionArn"] if created["CollectionArn"].startswith("arn:") else "arn:" + created["CollectionArn"]
    # empirical AWS quirk: CreateCollection's CollectionArn sometimes omits the "arn:" partition
    # prefix while DescribeCollection's CollectionARN is always fully qualified; tolerate that
    # specific shape while still requiring the two to name the same underlying resource.
    assert described["CollectionARN"] == fixed_created_arn, (
        described["CollectionARN"][-20:] + "|" + fixed_created_arn[-20:]
    )

    assert described["FaceModelVersion"] == face_model_version, (
        f"{described['FaceModelVersion']} != {face_model_version}"
    )
    assert described["FaceCount"] == 0, described["FaceCount"]
    assert described["UserCount"] == 0, described["UserCount"]

    rek.delete_collection(CollectionId=collection_id)

    not_found_message = f"Collection:{collection_id} not found!"

    code, message = _client_error(lambda: rek.describe_collection(CollectionId=collection_id))
    assert code == "ResourceNotFoundException", f"describe after delete: {code}"
    assert message == not_found_message, f"describe after delete message: {message!r}"

    redelete_code, redelete_message = _client_error(lambda: rek.delete_collection(CollectionId=collection_id))
    assert redelete_code == "ResourceNotFoundException", f"delete of already-deleted collection: {redelete_code}"
    assert redelete_message == not_found_message, (
        f"delete of already-deleted collection message: {redelete_message!r}"
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


def _describe_when_visible(rek, collection_id: str, *, timeout_s: float, interval_s: float = 2.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rek.describe_collection(CollectionId=collection_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


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
