"""list-cidr-locations-unknown-collection-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-cidr-locations-unknown-collection-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCidrLocations against a well-formed but nonexistent CidrCollectionId
    returns NoSuchCidrCollectionException, while a real collection still lists fine."""
    route53 = ctx.client("route53")

    collection_name = ctx.unique_name("sim2real-cidrloc-")
    created = route53.create_cidr_collection(Name=collection_name, CallerReference=str(uuid.uuid4()))
    collection_id = created["Collection"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_cidr_collection(Id=collection_id))

    # Positive control: a real, empty collection lists successfully with no locations.
    real_resp = route53.list_cidr_locations(CollectionId=collection_id)
    assert real_resp["CidrLocations"] == [], f"expected [], got {real_resp['CidrLocations']!r}"

    bogus_id = str(uuid.uuid4())  # well-formed UUID, but not a real collection
    code, message = _client_error(lambda: route53.list_cidr_locations(CollectionId=bogus_id))
    assert code == "NoSuchCidrCollectionException", f"expected NoSuchCidrCollectionException, got {code}"
    expected_message = ""  # AWS sends this error with an empty Message
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The failed lookup on the bogus id must not have affected the real collection.
    real_resp_again = route53.list_cidr_locations(CollectionId=collection_id)
    assert real_resp_again["CidrLocations"] == [], (
        f"expected [], got {real_resp_again['CidrLocations']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchCidrCollectionException, but call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
