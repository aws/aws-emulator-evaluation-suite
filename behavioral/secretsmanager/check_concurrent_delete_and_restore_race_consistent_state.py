"""concurrent-delete-and-restore-race-consistent-state."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-delete-and-restore-race-consistent-state"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]

_MARKED_FOR_DELETION = "You can't perform this operation on the secret because it was marked for deletion."


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Racing DeleteSecret and RestoreSecret leaves a consistent state: DeletedDate present and
    GetSecretValue rejected, or DeletedDate absent and GetSecretValue returns the original value;
    both states are then graded in sequence on every run."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-delrestrace-")
    created = sm.create_secret(
        Name=name, SecretString="payload", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _force_delete(sm, arn))

    def _delete():
        return sm.delete_secret(SecretId=arn)

    def _restore():
        return sm.restore_secret(SecretId=arn)

    # Which call "wins" the race is not something real AWS guarantees; the invariant under
    # test is that whichever way it resolves, the resulting state is self-consistent below.
    _run_concurrent([_delete, _restore])

    desc = sm.describe_secret(SecretId=arn)
    if "DeletedDate" in desc:
        code, message = _refusal(lambda: sm.get_secret_value(SecretId=arn))
        assert code == "InvalidRequestException", (
            f"secret has DeletedDate set but GetSecretValue returned {code!r} instead of "
            "InvalidRequestException"
        )
        assert message == _MARKED_FOR_DELETION, (
            f"unexpected refusal message for a secret marked for deletion: {message!r}"
        )
    else:
        resp = sm.get_secret_value(SecretId=arn)
        assert resp["SecretString"] == "payload", (
            f"secret has no DeletedDate but GetSecretValue returned SecretString={resp['SecretString']!r} "
            "instead of the original 'payload'"
        )
        assert resp["ARN"] == arn, f"expected ARN {arn!r}, got {resp['ARN']!r}"

    # Grade both terminal states on every run, whichever way the race resolved: bring the secret
    # back to active, then delete and restore it in sequence.
    if "DeletedDate" in desc:
        sm.restore_secret(SecretId=arn)
    sm.delete_secret(SecretId=arn)
    deleted = sm.describe_secret(SecretId=arn)
    assert "DeletedDate" in deleted, f"DeleteSecret did not set DeletedDate: {deleted!r}"
    code, message = _refusal(lambda: sm.get_secret_value(SecretId=arn))
    assert code == "InvalidRequestException", (
        f"secret marked for deletion: GetSecretValue returned {code!r} instead of "
        "InvalidRequestException"
    )
    assert message == _MARKED_FOR_DELETION, (
        f"unexpected refusal message for a secret marked for deletion: {message!r}"
    )
    sm.restore_secret(SecretId=arn)
    restored = sm.describe_secret(SecretId=arn)
    assert "DeletedDate" not in restored, f"RestoreSecret did not clear DeletedDate: {restored!r}"
    resp = sm.get_secret_value(SecretId=arn)
    assert resp["SecretString"] == "payload", (
        f"restored secret returned SecretString={resp['SecretString']!r} instead of 'payload'"
    )


def _force_delete(sm, arn: str) -> None:
    try:
        sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _refusal(fn):
    """Call fn() and return (Error.Code, Error.Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _run_concurrent(fns):
    from botocore.exceptions import ClientError

    def _wrap(fn):
        try:
            return fn(), None
        except ClientError as exc:
            return None, exc.response["Error"]["Code"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, fn) for fn in fns]
        return [f.result() for f in futures]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
