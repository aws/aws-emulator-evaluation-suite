"""restore-nonexistent-secret-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected RestoreSecret to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "restore-nonexistent-secret-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreSecret on a SecretId that was never created raises ResourceNotFoundException."""
    sm = ctx.client("secretsmanager")
    missing = ctx.unique_name("sim2real-behav-missing-")
    code, message = _error_code(lambda: sm.restore_secret(SecretId=missing))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Secrets Manager can't find the specified secret.", f"unexpected not-found message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
