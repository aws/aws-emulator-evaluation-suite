"""cidr-locations-unknown-collection-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "cidr-locations-unknown-collection-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCidrLocations against a nonexistent collection id raises NoSuchCidrCollectionException,
    while the same call against a real collection succeeds (in-file positive control)."""
    r53 = ctx.client("route53")
    collection_name = ctx.unique_name("sim2reals-cidrcoll-")
    created = r53.create_cidr_collection(
        Name=collection_name, CallerReference=str(uuid.uuid4())
    )
    collection_id = created["Collection"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_cidr_collection(Id=collection_id))

    # Positive control: a real, empty collection lists successfully (empty is fine).
    ok = r53.list_cidr_locations(CollectionId=collection_id)
    assert ok["CidrLocations"] == [], f"expected no locations on a fresh collection, got {ok['CidrLocations']!r}"

    # Negative: a syntactically-valid but nonexistent collection id must be rejected,
    # not silently treated as an empty collection.
    bogus_id = str(uuid.uuid4())
    code, message = _error(lambda: r53.list_cidr_locations(CollectionId=bogus_id))
    assert code == "NoSuchCidrCollectionException", f"expected NoSuchCidrCollectionException, got {code}"
    # AWS returns this refusal with an empty message.
    assert message == "", f"expected an empty message, got {message!r}"

    # The failed lookup on the bogus id must not have disturbed the real collection.
    ok_again = r53.list_cidr_locations(CollectionId=collection_id)
    assert ok_again["CidrLocations"] == [], (
        f"real collection {collection_id} changed after an unrelated failed lookup: {ok_again['CidrLocations']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
