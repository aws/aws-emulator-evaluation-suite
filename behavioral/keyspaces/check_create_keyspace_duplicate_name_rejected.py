"""create-keyspace-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-keyspace-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a keyspace whose name already exists is rejected with ConflictException, leaves
    the original keyspace's resourceArn untouched, while a differently-named keyspace still
    creates fine (positive control)."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    check_tags = [{"key": "sim2real-check", "value": CHECK}]

    arn = kc.create_keyspace(keyspaceName=ks_name, tags=check_tags)["resourceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    # ListKeyspaces can lag briefly behind a just-issued CreateKeyspace; wait for the
    # keyspace to become visible there before using list-membership as an assertion oracle.
    _wait_listed(kc, ks_name)

    code, message = _error(lambda: kc.create_keyspace(keyspaceName=ks_name))
    assert code == "ConflictException", f"expected ConflictException for duplicate keyspace name, got {code}"
    expected_message = f"Cannot add existing keyspace {ks_name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected duplicate must not have replaced the original keyspace...
    current_arn = kc.get_keyspace(keyspaceName=ks_name)["resourceArn"]
    assert current_arn == arn, f"rejected duplicate create changed the keyspace's resourceArn: expected {arn}, got {current_arn}"
    # ...nor produced a second entry alongside it
    keyspaces = kc.list_keyspaces()["keyspaces"]
    matches = [k for k in keyspaces if k["keyspaceName"] == ks_name]
    assert len(matches) == 1, f"duplicate create must not create a second keyspace, found {len(matches)}"

    # positive control: creating a keyspace with a fresh, unused name still works
    other_name = _kname(ctx, "sim2real_behav_ks_ctrl")
    other_arn = kc.create_keyspace(keyspaceName=other_name, tags=check_tags)["resourceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=other_name)))
    assert other_arn != arn, f"control keyspace must get its own resourceArn, got the original's {arn}"
    _wait_listed(kc, other_name)


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_listed(kc, ks_name: str, timeout_s: float = 60.0) -> None:
    import time
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        names = [k["keyspaceName"] for k in kc.list_keyspaces()["keyspaces"]]
        if ks_name in names:
            return
        time.sleep(2.0)
    raise AssertionError(f"keyspace {ks_name} never appeared in ListKeyspaces")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
