"""op-contract-deleteKeyValueStore."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteKeyValueStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKeyValueStore: an incorrect IfMatch is rejected distinctly, a correct delete
    removes the store so Describe reports NotFound, and the dead store also refuses a
    second delete rather than merely disappearing from reads."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")

    created = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )

    def _cleanup(name=name):
        try:
            fresh = cf.describe_key_value_store(Name=name)
            cf.delete_key_value_store(Name=name, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: garbled IfMatch while the store still exists
    bad_code, bad_message = _error(
        lambda: cf.delete_key_value_store(Name=name, IfMatch='"bogus-etag"')
    )
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # success path: wait for the store to leave a transient provisioning state, then delete
    ready_etag = _wait_kvs_ready(ctx, name)
    cf.delete_key_value_store(Name=name, IfMatch=ready_etag)
    gone_code, gone_message = _error(lambda: cf.describe_key_value_store(Name=name))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    assert gone_message == "The specified KeyValueStore does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # the dead store is unusable, not just absent from reads: a second delete on the same
    # id also refuses, rather than silently no-op'ing or succeeding again
    second_delete_code, second_delete_message = _error(
        lambda: cf.delete_key_value_store(Name=name, IfMatch=ready_etag)
    )
    assert second_delete_code == "EntityNotFound", (
        f"expected EntityNotFound on double delete, got {second_delete_code}"
    )
    assert second_delete_message == "The specified KeyValueStore does not exist.", (
        f"expected the exact refusal message, got {second_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_kvs_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cf.describe_key_value_store(Name=name)
        last_status = resp["KeyValueStore"]["Status"]
        if last_status != "PROVISIONING":
            return resp["ETag"]
        time.sleep(interval_s)
    raise TimeoutError(
        f"key value store {name!r} did not leave PROVISIONING within {timeout_s}s, "
        f"last status={last_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
