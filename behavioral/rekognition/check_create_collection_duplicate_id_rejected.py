"""create-collection-duplicate-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-collection-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCollection with an existing id is rejected with ResourceAlreadyExistsException and its exact
    message, leaving the original's ARN unchanged; another id succeeds, and the id is reusable once
    the original is deleted."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-dupe-")
    other_id = ctx.unique_name("sim2real-rek-dupe-other-")

    created = rek.create_collection(CollectionId=collection_id)
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, collection_id))
    assert created["StatusCode"] == 200, (
        f"positive control: CreateCollection({collection_id!r}) should succeed with StatusCode 200, "
        f"got {created!r}"
    )
    original_arn = created["CollectionArn"]

    code, message = _client_error(lambda: rek.create_collection(CollectionId=collection_id))
    assert code == "ResourceAlreadyExistsException", (
        f"CreateCollection with the already-taken id {collection_id!r} should be rejected with "
        f"ResourceAlreadyExistsException, got {code!r}"
    )
    assert message == f"The collection id: {collection_id} already exists", (
        f"CreateCollection with the already-taken id {collection_id!r} returned message {message!r}"
    )

    # effect absent: the original collection is untouched (same ARN, still describable)
    described = rek.describe_collection(CollectionId=collection_id)
    fixed_original_arn = original_arn if original_arn.startswith("arn:") else "arn:" + original_arn
    # CreateCollection's CollectionArn sometimes omits the "arn:" partition
    # prefix while DescribeCollection's CollectionARN is always fully qualified.
    assert described["CollectionARN"] == fixed_original_arn, (
        f"the rejected duplicate create changed the original collection's ARN: expected "
        f"{fixed_original_arn!r}, got {described['CollectionARN']!r}"
    )

    # positive control: a genuinely new CollectionId still succeeds
    control = rek.create_collection(CollectionId=other_id)
    ctx.on_cleanup(lambda: _delete_collection_ignore_missing(rek, other_id))
    assert control["StatusCode"] == 200, (
        f"CreateCollection with the genuinely new id {other_id!r} should succeed with StatusCode "
        f"200, got {control!r}"
    )

    # restore: the conflict is state (an existing collection), not the id itself -- delete the
    # original, prove it is genuinely gone, then the identical CollectionId must succeed again.
    rek.delete_collection(CollectionId=collection_id)
    gone_code, gone_message = _client_error(lambda: rek.describe_collection(CollectionId=collection_id))
    assert gone_code == "ResourceNotFoundException", (
        f"after deleting {collection_id!r}, DescribeCollection should fail with "
        f"ResourceNotFoundException, got {gone_code!r}"
    )
    assert gone_message == f"Collection:{collection_id} not found!", (
        f"after deleting {collection_id!r}, DescribeCollection returned message {gone_message!r}"
    )
    restored = rek.create_collection(CollectionId=collection_id)
    assert restored["StatusCode"] == 200, (
        f"the identical CollectionId {collection_id!r} should be creatable again once the original "
        f"collection holding it was deleted, got {restored!r}"
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
