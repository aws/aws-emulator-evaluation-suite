"""op-contract-describeKeyValueStore."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeKeyValueStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeKeyValueStore: reflects a freshly created store transitioning
    to READY, and rejects an unknown store name (EntityNotFound)."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")

    created = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    assert created["KeyValueStore"]["Name"] == name, (
        f"expected KeyValueStore Name {name!r}, got {created['KeyValueStore']['Name']!r}"
    )
    created_arn = created["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete(cf, name))

    status = _poll_until(
        lambda: cf.describe_key_value_store(Name=name)["KeyValueStore"]["Status"],
        lambda s: s.upper() == "READY",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert status.upper() == "READY", f"expected READY, got {status}"

    described = cf.describe_key_value_store(Name=name)
    # The ARN identifies the store by its own KeyValueStore Id, not by Name,
    # so compare against the ARN returned at creation time rather than
    # asserting a Name suffix.
    assert described["KeyValueStore"]["ARN"] == created_arn, (
        f"expected ARN {created_arn!r}, got {described['KeyValueStore']['ARN']!r}"
    )
    assert described["KeyValueStore"]["Name"] == name, (
        f"expected KeyValueStore Name {name!r}, got {described['KeyValueStore']['Name']!r}"
    )

    # distinct error boundary: unknown store name
    code, msg = _error(lambda: cf.describe_key_value_store(Name=name + "-does-not-exist"))
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assert msg == "The specified KeyValueStore does not exist.", f"unexpected EntityNotFound message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _safe_delete(cf, name: str) -> None:
    try:
        current = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
