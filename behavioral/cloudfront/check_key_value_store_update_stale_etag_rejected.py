"""key-value-store-update-stale-etag-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-value-store-update-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts a stale ETag is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_ready(cf, name: str) -> dict:
    deadline = time.monotonic() + 180.0
    last = cf.describe_key_value_store(Name=name)
    while last["KeyValueStore"]["Status"] != "READY":
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"key value store {name!r} did not reach READY within 180s, "
                f"last status={last['KeyValueStore']['Status']!r}"
            )
        time.sleep(3.0)
        last = cf.describe_key_value_store(Name=name)
    return last


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateKeyValueStore with a stale If-Match ETag is rejected and the store's Comment is
    NOT changed; the same update succeeds once the caller supplies the CURRENT ETag."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-stale-")

    created = cf.create_key_value_store(
        Name=name,
        Comment="original-comment",
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    stale_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            e = cf.describe_key_value_store(Name=name)["ETag"]
            cf.delete_key_value_store(Name=name, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    described = _wait_ready(cf, name)
    # Rotate the ETag with a real update, so `stale_etag` no longer matches the live version.
    cf.update_key_value_store(Name=name, IfMatch=described["ETag"], Comment="rotated-comment")

    code, message = _error(
        lambda: cf.update_key_value_store(Name=name, IfMatch=stale_etag, Comment="attacker-comment")
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}"
    assert message == (
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    ), f"expected AWS's exact precondition message, got {message!r}"

    # The forbidden effect did not happen: the comment is still the rotated one, not the
    # rejected "attacker-comment".
    unchanged = cf.describe_key_value_store(Name=name)
    assert unchanged["KeyValueStore"]["Comment"] == "rotated-comment", (
        f"stale-etag update must not change the comment, got {unchanged['KeyValueStore']['Comment']!r}"
    )

    # Positive control: the same update succeeds with the CURRENT ETag.
    current_etag = unchanged["ETag"]
    cf.update_key_value_store(Name=name, IfMatch=current_etag, Comment="final-comment")

    # Independent read at the destination, through a different operation than the one
    # that mutated: the store now reports the final comment, not the rejected one.
    final = cf.describe_key_value_store(Name=name)
    assert final["KeyValueStore"]["Comment"] == "final-comment", (
        f"expected final-comment after IfMatch-current update, got {final['KeyValueStore']['Comment']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
