"""delete-secret-conflicting-recovery-params-fails."""
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
    """Poll fn() until it raises `expected` (force-delete isn't read-after-write); return the last (code, message)."""
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
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "delete-secret-conflicting-recovery-params-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSecret must reject RecoveryWindowInDays combined with ForceDeleteWithoutRecovery."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    code, message = _error(
        lambda: sm.delete_secret(
            SecretId=name, RecoveryWindowInDays=7, ForceDeleteWithoutRecovery=True
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays.", (
        f"unexpected refusal message: {message!r}"
    )

    # Effect absent: the rejected call must not have scheduled deletion, and the
    # secret must still be fully intact and usable afterwards.
    described = sm.describe_secret(SecretId=name)
    assert described.get("DeletedDate") is None, f"unexpected DeletedDate: {described.get('DeletedDate')}"
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "initial-value"

    # Positive control: the identical call with only one of the two mutually
    # exclusive parameters succeeds and takes effect, proving DeleteSecret itself
    # works on this target and the prior rejection was specific to the conflict.
    sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    gone_code, gone_message = _wait_for_error(
        lambda: sm.describe_secret(SecretId=name), "ResourceNotFoundException"
    )
    assert gone_code == "ResourceNotFoundException", f"expected secret gone, got {gone_code}"
    assert gone_message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
