"""put-account-setting-invalid-value-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-setting-invalid-value-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSetting with a valid value is applied and listed, while a value outside the
    setting's enum is refused InvalidParameterException "Invalid setting 'value'" and the listed
    value is unchanged."""
    ecs = ctx.client("ecs")

    before = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    ).get("settings", [])
    before_value = before[0]["value"] if before else "disabled"
    control_value = "disabled" if before_value != "disabled" else "enabled"

    ctx.on_cleanup(
        lambda: ecs.put_account_setting(name="containerInsights", value=before_value)
    )

    # Positive control: the setting is otherwise writable for this principal.
    put_resp = ecs.put_account_setting(
        name="containerInsights", value=control_value
    )["setting"]
    assert put_resp["value"] == control_value, put_resp
    listed = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    )["settings"]
    assert listed and listed[0]["value"] == control_value, listed

    # Negative: a value outside the accepted enum is rejected.
    code, message = _error(
        lambda: ecs.put_account_setting(
            name="containerInsights", value="not-a-real-value"
        )
    )
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    assert message == "Invalid setting 'value'", message

    # Effect absent: the forbidden write never took effect — an independent
    # read still shows the control value, not the rejected one.
    after = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    )["settings"]
    assert after and after[0]["value"] == control_value, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
