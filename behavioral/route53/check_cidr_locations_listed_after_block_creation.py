"""cidr-locations-listed-after-block-creation."""
from __future__ import annotations

import random
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cidr-locations-listed-after-block-creation"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCidrLocations reflects location names added via ChangeCidrCollection."""
    r53 = ctx.client("route53")
    collection_name = ctx.unique_name("sim2reals-cidrcoll-")
    created = r53.create_cidr_collection(
        Name=collection_name, CallerReference=str(uuid.uuid4())
    )
    collection_id = created["Collection"]["Id"]

    # Pick a private-range octet at random per run so repeated runs never collide
    # with a leftover CIDR block from a previous, incompletely-cleaned-up run.
    octet = random.randint(1, 254)
    cidr_a = f"10.{octet}.0.0/24"
    cidr_b = f"10.{octet}.1.0/24"

    def _cleanup() -> None:
        try:
            r53.change_cidr_collection(
                Id=collection_id,
                Changes=[
                    {
                        "LocationName": "loc-a",
                        "Action": "DELETE_IF_EXISTS",
                        "CidrList": [cidr_a],
                    },
                    {
                        "LocationName": "loc-b",
                        "Action": "DELETE_IF_EXISTS",
                        "CidrList": [cidr_b],
                    },
                ],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCidrCollectionException":
                raise
        try:
            r53.delete_cidr_collection(Id=collection_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCidrCollectionException":
                raise

    ctx.on_cleanup(_cleanup)

    r53.change_cidr_collection(
        Id=collection_id,
        Changes=[
            {"LocationName": "loc-a", "Action": "PUT", "CidrList": [cidr_a]},
            {"LocationName": "loc-b", "Action": "PUT", "CidrList": [cidr_b]},
        ],
    )

    names = _poll_cidr_location_names(r53, collection_id, {"loc-a", "loc-b"}, timeout_s=30.0)
    assert {"loc-a", "loc-b"} <= names, f"expected loc-a/loc-b in {names}"

    # And the actual CIDR blocks under each location match exactly what we PUT
    # (not just "contains" — a fresh location should hold nothing else).
    blocks_a = {b["CidrBlock"] for b in r53.list_cidr_blocks(CollectionId=collection_id, LocationName="loc-a")["CidrBlocks"]}
    assert blocks_a == {cidr_a}, f"expected loc-a blocks == {{{cidr_a}}}, got {blocks_a}"

    blocks_b = {b["CidrBlock"] for b in r53.list_cidr_blocks(CollectionId=collection_id, LocationName="loc-b")["CidrBlocks"]}
    assert blocks_b == {cidr_b}, f"expected loc-b blocks == {{{cidr_b}}}, got {blocks_b}"


def _poll_cidr_location_names(r53, collection_id, expected, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    names: set = set()
    while time.monotonic() < deadline:
        resp = r53.list_cidr_locations(CollectionId=collection_id)
        names = {loc["LocationName"] for loc in resp["CidrLocations"]}
        if expected <= names:
            return names
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected} in CIDR locations, last saw {names}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
