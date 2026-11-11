"""delete-secret-force-immediate."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_SUCCEEDED = "<call succeeded>"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A SUCCESS returns
    (_SUCCEEDED, None), a code no AWS error can equal, so a poll keeps waiting and a final
    assert fails loudly."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return _SUCCEEDED, None

def _wait_for_error(fn, expected, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it raises `expected` (transitions aren't read-after-write); return the last (code, message)."""
    deadline = time.time() + timeout_s
    last = _error(fn)
    while last[0] != expected and time.time() < deadline:
        time.sleep(interval_s)
        last = _error(fn)
    return last

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name, "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-check"}]}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

def _wait_for_success(fn, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it stops raising ClientError; return its result or re-raise the last error."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.time() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "delete-secret-force-immediate"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

_NOT_FOUND_MESSAGE = "Secrets Manager can't find the specified secret."

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret with ForceDeleteWithoutRecovery removes the secret immediately: an independent
    read reports it gone, a mutation on the dead id is rejected, and — unlike a recovery-window
    delete, which reserves the name for the whole window — the name is reusable right away."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)

    # Force-deletion is fast but not read-after-write consistent; poll.
    code, message = _wait_for_error(
        lambda: sm.describe_secret(SecretId=name), "ResourceNotFoundException"
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == _NOT_FOUND_MESSAGE, f"unexpected not-found message: {message!r}"

    # A mutation on the dead id fails with the same specific not-found code, not a generic error.
    mutate_code, mutate_message = _error(
        lambda: sm.update_secret(SecretId=name, Description="post-mortem")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == _NOT_FOUND_MESSAGE, (
        f"unexpected not-found message: {mutate_message!r}"
    )

    # Unlike a recovery-window delete (which reserves the name for the entire window), force
    # deletion frees the name immediately: CreateSecret with the identical name must now succeed.
    recreated = _wait_for_success(
        lambda: _create_secret(sm, ctx, name=name, secret_string="reincarnated")
    )
    assert recreated["Name"] == name, f"expected reused name {name!r}, got {recreated.get('Name')!r}"
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "reincarnated", (
        f"expected reincarnated value, got {val.get('SecretString')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
