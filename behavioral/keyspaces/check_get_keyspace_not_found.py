"""get-keyspace-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-keyspace-not-found"
GROUP = "error-semantics"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetKeyspace on a keyspace name that was never created returns ResourceNotFoundException,
    while the identical call against a keyspace this check just created succeeds -- proving the
    rejection is specific to absence rather than a client fault that would 404 every call."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    missing_name = _kname(ctx, "sim2real_behav_missing_ks")

    kc.create_keyspace(keyspaceName=ks_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))
    _wait_keyspace_visible(kc, ks_name)

    control = kc.get_keyspace(keyspaceName=ks_name)
    assert control["keyspaceName"] == ks_name, control

    code, message = _error(lambda: kc.get_keyspace(keyspaceName=missing_name))
    assert code == "ResourceNotFoundException", code
    expected_message = f"Keyspace {missing_name} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_keyspace_visible(kc, ks_name: str, timeout_s: float = 90.0) -> None:
    """CreateKeyspace is asynchronous: measured, GetKeyspace answered ResourceNotFoundException
    if issued immediately after."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.get_keyspace(keyspaceName=ks_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
