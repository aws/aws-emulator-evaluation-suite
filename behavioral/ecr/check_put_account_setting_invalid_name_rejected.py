"""put-account-setting-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "put-account-setting-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-account-setting")
def run(ctx) -> None:
    """PutAccountSetting on a name AWS does not recognize is rejected with
    InvalidParameterException and leaves the real setting unchanged; a recognized name
    (positive control) succeeds."""
    ecr = ctx.client("ecr")
    name = "BASIC_SCAN_TYPE_VERSION"

    before = ecr.get_account_setting(name=name)
    put = ecr.put_account_setting(name=name, value=before["value"])
    assert put["name"] == name, put
    assert put["value"] == before["value"], put

    expected = "Invalid parameter at 'name' failed to satisfy constraint: 'Invalid account setting name provided'"
    code, message = _error(
        lambda: ecr.put_account_setting(name="NOT_A_REAL_ECR_ACCOUNT_SETTING", value="AWS_NATIVE")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = ecr.get_account_setting(name=name)
    assert after["value"] == before["value"], (
        f"expected {name!r} unchanged at {before['value']!r}, got {after['value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
