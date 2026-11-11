"""account-setting-roundtrip."""
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
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

CHECK = "account-setting-roundtrip"
GROUP = 'registry-config'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-account-setting")
def run(ctx) -> None:
    """PutAccountSetting BASIC_SCAN_TYPE_VERSION=AWS_NATIVE round-trips via GetAccountSetting, and
    the retired value CLAIR is rejected with InvalidParameterException, leaving the value unchanged."""
    ecr = ctx.client("ecr")
    name = "BASIC_SCAN_TYPE_VERSION"

    put = ecr.put_account_setting(name=name, value="AWS_NATIVE")
    assert put["name"] == name, put
    assert put["value"] == "AWS_NATIVE", put

    got = ecr.get_account_setting(name=name)
    assert got["name"] == name, got
    assert got["value"] == "AWS_NATIVE", got

    code, message = _error(lambda: ecr.put_account_setting(name=name, value="CLAIR"))
    assert code == "InvalidParameterException", code
    assert message == f"You can't set '{name}' to 'CLAIR' in this region.", message

    after = ecr.get_account_setting(name=name)
    assert after["value"] == "AWS_NATIVE", after

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
