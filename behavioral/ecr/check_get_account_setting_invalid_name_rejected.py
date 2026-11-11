"""get-account-setting-invalid-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-account-setting-invalid-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountSetting with an unrecognized setting name is rejected with
    InvalidParameterException, while a recognized setting name (positive control)
    returns a concrete value."""
    ecr = ctx.client("ecr")

    ok_resp = ecr.get_account_setting(name="BASIC_SCAN_TYPE_VERSION")
    assert ok_resp["name"] == "BASIC_SCAN_TYPE_VERSION", ok_resp
    assert ok_resp["value"] in ("AWS_NATIVE", "CLAIR"), ok_resp

    code, message = _error(lambda: ecr.get_account_setting(name="NOT_A_REAL_ECR_ACCOUNT_SETTING"))
    assert code == "InvalidParameterException", code
    expected = "Invalid parameter at 'name' failed to satisfy constraint: 'Invalid account setting name provided'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
