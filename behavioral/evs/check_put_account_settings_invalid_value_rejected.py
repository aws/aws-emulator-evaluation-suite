"""put-account-settings-invalid-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-account-settings-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["evs"]

_SETTING_NAME = "vcfPortedCoreCount"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:evs-account-settings")
def run(ctx) -> None:
    """PutAccountSettings rejects a vcfPortedCoreCount value above the documented
    1,000,000 core maximum, leaving the account setting unchanged; a value within
    range is accepted and persisted (positive control)."""
    evs = ctx.client("evs")
    original_value = _current_value(evs)
    ctx.on_cleanup(lambda: _restore(evs, original_value))

    code, message = _error(
        lambda: evs.put_account_settings(
            settings=[{"name": _SETTING_NAME, "value": "50000000"}]
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a value above the 1,000,000 core "
        f"maximum, got {code!r}"
    )
    assert message == (
        f"Request validation failure: Setting '{_SETTING_NAME}' must not exceed 1000000."
    ), f"unexpected message {message!r}"
    unchanged = _current_value(evs)
    assert unchanged == original_value, (
        f"expected {_SETTING_NAME} to stay {original_value!r} after the "
        f"rejected put, got {unchanged!r}"
    )

    evs.put_account_settings(settings=[{"name": _SETTING_NAME, "value": "42"}])
    persisted = _current_value(evs)
    assert persisted == "42", (
        f"expected {_SETTING_NAME} to persist as '42' after an in-range put, "
        f"got {persisted!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _current_value(evs):
    settings = evs.get_account_settings()["settings"]
    for setting in settings:
        if setting["name"] == _SETTING_NAME:
            return setting["value"]
    return None


def _restore(evs, original_value):
    if original_value is None:
        # There is no delete-setting API; leave a neutral marker rather than the
        # test's own probe value so a fresh account isn't left with "42".
        evs.put_account_settings(settings=[{"name": _SETTING_NAME, "value": "0"}])
    else:
        evs.put_account_settings(
            settings=[{"name": _SETTING_NAME, "value": original_value}]
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
