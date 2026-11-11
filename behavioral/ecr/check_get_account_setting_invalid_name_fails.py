"""get-account-setting-invalid-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "get-account-setting-invalid-name-fails"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountSetting on an unknown setting name is refused InvalidParameterException with the
    exact message, while BASIC_SCAN_TYPE_VERSION returns AWS_NATIVE or CLAIR."""
    ecr = ctx.client("ecr")

    ok = ecr.get_account_setting(name="BASIC_SCAN_TYPE_VERSION")
    assert ok["name"] == "BASIC_SCAN_TYPE_VERSION", ok
    assert ok["value"] in ("AWS_NATIVE", "CLAIR"), ok

    code, message = _error(lambda: ecr.get_account_setting(name="not-a-real-setting"))
    assert code == "InvalidParameterException", code
    expected = "Invalid parameter at 'name' failed to satisfy constraint: 'Invalid account setting name provided'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
