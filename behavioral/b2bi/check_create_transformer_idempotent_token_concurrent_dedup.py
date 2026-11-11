"""create-transformer-idempotent-token-concurrent-dedup."""
from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-transformer-idempotent-token-concurrent-dedup"
GROUP = "concurrency"
SERVICES = ["b2bi"]

CONFLICT_MESSAGE = (
    "This clientToken has been used for a previous request that is still being processed."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateTransformer calls sharing one clientToken create exactly one
    transformer: every success and a later replay return the same transformerId, and any
    racer that overlaps the in-flight original gets ConflictException, never a duplicate."""
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-tr-")
    client_token = ctx.unique_name("sim2real-b2bi-token-")
    racers = 5
    barrier = threading.Barrier(racers)

    def _create():
        return b2bi.create_transformer(
            name=name,
            inputConversion={
                "fromFormat": "X12",
                "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            },
            mapping={"templateLanguage": "JSONATA", "template": "$"},
            clientToken=client_token,
            tags=[{"Key": "sim2real-created-with", "Value": CHECK}],
        )

    def _race():
        barrier.wait(timeout=30)
        return _create()

    results = []
    errors = []
    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_race) for _ in range(racers)]
        for fut in futures:
            try:
                results.append(fut.result())
            except ClientError as err:
                error = err.response["Error"]
                errors.append((error["Code"], error.get("Message")))

    assert results, f"expected at least one of {racers} concurrent racers to succeed, all failed: {errors}"
    transformer_ids = {r["transformerId"] for r in results}
    assert len(transformer_ids) == 1, (
        f"expected all successful concurrent CreateTransformer calls sharing a clientToken to "
        f"share a single transformerId, got {transformer_ids}"
    )
    transformer_id = transformer_ids.pop()
    assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", transformer_id), (
        f"expected a TransformerId matching the documented pattern, got {transformer_id!r}"
    )
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))

    # A racer only loses if it overlaps the in-flight original; a non-overlapping call is a
    # legal replay, so a loser is graded when one occurs but is not required.
    assert all(error == ("ConflictException", CONFLICT_MESSAGE) for error in errors), (
        f"expected losing racers to fail with ConflictException {CONFLICT_MESSAGE!r}, got {errors}"
    )

    # A replay with the identical clientToken, issued after the original request has
    # completed, must return the SAME transformerId rather than minting a second transformer.
    replay = _create()
    assert replay["transformerId"] == transformer_id, (
        f"expected a replayed CreateTransformer call with the same clientToken to return the "
        f"original transformerId {transformer_id!r}, got {replay['transformerId']!r}"
    )

    matching = [
        t
        for page_token in _all_pages(b2bi)
        for t in page_token
        if t["name"] == name
    ]
    assert len(matching) == 1, (
        f"expected exactly one transformer named {name!r} to exist after the race, found {len(matching)}"
    )
    assert matching[0]["transformerId"] == transformer_id, (
        f"expected the listed transformer named {name!r} to have transformerId "
        f"{transformer_id!r}, got {matching[0]['transformerId']!r}"
    )


def _all_pages(b2bi):
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = b2bi.list_transformers(**kwargs)
        yield page["transformers"]
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
