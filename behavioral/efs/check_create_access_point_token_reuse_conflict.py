"""create-access-point-token-reuse-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-point-token-reuse-conflict"
GROUP = "error-semantics"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccessPoint repeated with the same ClientToken and parameters fails with AccessPointAlreadyExists
    and its exact message while the original exists; once it is deleted (AccessPointNotFound), the same
    token creates a new access point with a new id.
    """
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    ap_token = ctx.unique_name("sim2real-efs-ap-")
    kwargs = dict(
        ClientToken=ap_token,
        FileSystemId=fs_id,
        RootDirectory={"Path": "/idempotent-test"},
    )
    first = efs.create_access_point(**kwargs)
    ap_id = first["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))

    code, msg = _client_error(lambda: efs.create_access_point(**kwargs))
    assert code == "AccessPointAlreadyExists", f"expected AccessPointAlreadyExists, got {code!r}"
    expected_msg = None  # AWS sends this error with no Message member
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # exactly one access point exists for this token — the rejected retry created nothing
    all_aps = efs.describe_access_points(FileSystemId=fs_id)["AccessPoints"]
    matching = [ap for ap in all_aps if ap["ClientToken"] == ap_token]
    assert len(matching) == 1, f"expected exactly 1 access point for token {ap_token!r}, found {len(matching)}"

    # restore leg: delete the access point the token is bound to, then prove the delete is
    # real (independent read 404s, a second mutation on the dead id also 404s) before asking
    # whether the token itself — not just the live resource — is what AWS keys the conflict on
    efs.delete_access_point(AccessPointId=ap_id)
    _wait_ap_gone(efs, ap_id)
    not_found_code, not_found_msg = _client_error(lambda: efs.describe_access_points(AccessPointId=ap_id))
    assert not_found_code == "AccessPointNotFound", f"expected AccessPointNotFound, got {not_found_code!r}"
    expected_describe_msg = f"Access point '{ap_id}' does not exist."
    assert not_found_msg == expected_describe_msg, (
        f"expected message {expected_describe_msg!r}, got {not_found_msg!r}"
    )
    redelete_code, redelete_msg = _client_error(lambda: efs.delete_access_point(AccessPointId=ap_id))
    assert redelete_code == "AccessPointNotFound", f"expected second delete to 404 too, got {redelete_code!r}"
    expected_redelete_msg = f"Access point '{ap_id}' does not exist."
    assert redelete_msg == expected_redelete_msg, (
        f"expected message {expected_redelete_msg!r}, got {redelete_msg!r}"
    )

    retry_ap_id = None
    try:
        retry = efs.create_access_point(**kwargs)
        retry_ap_id = retry["AccessPointId"]
        ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, retry_ap_id))
        retry_code = None
    except ClientError as e:
        retry_code = e.response["Error"]["Code"]
    assert retry_code is None, (
        f"expected the identical token+params to succeed once the original access point "
        f"was deleted — the conflict is keyed on the live resource, not a permanently spent "
        f"token — got code={retry_code!r}"
    )
    assert retry_ap_id is not None and retry_ap_id != ap_id, (
        f"expected a freshly-created access point distinct from the deleted one, "
        f"got {retry_ap_id!r} (original was {ap_id!r})"
    )

    # independent read at the destination: the reused token really did mint a new resource
    retry_ap = efs.describe_access_points(AccessPointId=retry_ap_id)["AccessPoints"][0]
    assert retry_ap["RootDirectory"]["Path"] == "/idempotent-test", (
        f"expected the retried access point's root directory to match, got {retry_ap['RootDirectory']!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_ap_gone(efs, ap_id, timeout_s=60.0):
    def probe():
        try:
            efs.describe_access_points(AccessPointId=ap_id)
            return "present"
        except ClientError as e:
            return e.response["Error"]["Code"]

    return _poll_until(
        probe,
        lambda code: code == "AccessPointNotFound",
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


def _delete_ap_best_effort(efs, ap_id):
    try:
        efs.delete_access_point(AccessPointId=ap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessPointNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
