"""key-value-store-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-value-store-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_READY_TIMEOUT_S = 180.0
_READY_INTERVAL_S = 3.0


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_ready(cf, name: str) -> dict:
    """KeyValueStore briefly reports a provisioning-ish status right after creation before
    settling; poll DescribeKeyValueStore until its ETag is stable/usable for a mutation."""
    deadline = time.monotonic() + _READY_TIMEOUT_S
    last = cf.describe_key_value_store(Name=name)
    while last["KeyValueStore"]["Status"] != "READY":
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"KeyValueStore {name!r} did not reach READY within {_READY_TIMEOUT_S}s, "
                f"last status={last['KeyValueStore']['Status']!r}"
            )
        time.sleep(_READY_INTERVAL_S)
        last = cf.describe_key_value_store(Name=name)
    return last


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """KeyValueStore create->describe->update->delete lifecycle and disappearance from list,
    with ETag rotating on update and Comment mutated in place (Name stays immutable)."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")

    created = cf.create_key_value_store(
        Name=name,
        Comment="initial-comment",
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    kvs_arn = created["KeyValueStore"]["ARN"]
    etag0 = created["ETag"]
    assert created["KeyValueStore"]["Name"] == name, (
        f"expected Name {name!r}, got {created['KeyValueStore']['Name']!r}"
    )
    assert created["KeyValueStore"]["Comment"] == "initial-comment", (
        f"expected Comment 'initial-comment', got {created['KeyValueStore']['Comment']!r}"
    )

    def _cleanup() -> None:
        try:
            e = cf.describe_key_value_store(Name=name)["ETag"]
            cf.delete_key_value_store(Name=name, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    described = _wait_ready(cf, name)
    assert described["KeyValueStore"]["ARN"] == kvs_arn, (
        f"expected ARN {kvs_arn!r}, got {described['KeyValueStore']['ARN']!r}"
    )

    listing = cf.list_key_value_stores()
    names = [i["Name"] for i in listing.get("KeyValueStoreList", {}).get("Items", []) or []]
    assert name in names, f"expected {name!r} in list_key_value_stores(), got {names!r}"

    updated = cf.update_key_value_store(
        Name=name, IfMatch=described["ETag"], Comment="updated-comment"
    )
    etag1 = updated["ETag"]
    assert etag1 != etag0, f"expected ETag to rotate on update, both were {etag0!r}"
    assert updated["KeyValueStore"]["Comment"] == "updated-comment", (
        f"expected Comment 'updated-comment', got {updated['KeyValueStore']['Comment']!r}"
    )
    assert updated["KeyValueStore"]["Name"] == name, (
        f"expected Name to stay {name!r}, got {updated['KeyValueStore']['Name']!r}"
    )

    described2 = _wait_ready(cf, name)
    cf.delete_key_value_store(Name=name, IfMatch=described2["ETag"])

    code, message = _error(lambda: cf.describe_key_value_store(Name=name))
    assert code == "EntityNotFound", f"expected 404 EntityNotFound, got {code!r}"
    assert message == "The specified KeyValueStore does not exist.", (
        f"expected AWS's exact not-found message for the deleted store, got {message!r}"
    )

    # The delete didn't just make the store unreadable: a mutation against the dead
    # id must also fail, with the same not-found code as the read.
    mutate_code, mutate_message = _error(
        lambda: cf.update_key_value_store(Name=name, IfMatch=etag1, Comment="post-delete-comment")
    )
    assert mutate_code == "EntityNotFound", (
        f"expected update on deleted store to fail EntityNotFound, got {mutate_code!r}"
    )
    assert mutate_message == "The specified KeyValueStore does not exist.", (
        f"expected AWS's exact not-found message updating the deleted store, got {mutate_message!r}"
    )

    listing2 = cf.list_key_value_stores()
    names2 = [i["Name"] for i in listing2.get("KeyValueStoreList", {}).get("Items", []) or []]
    assert name not in names2, f"expected {name!r} absent from list_key_value_stores(), got {names2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
