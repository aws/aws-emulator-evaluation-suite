"""op-contract-put-account-setting."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-put-account-setting"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSetting persists the value for the calling principal (round-trips through
    ListAccountSettings); an unsupported value is rejected with InvalidParameterException
    and the prior setting is left unchanged."""
    ecs = ctx.client("ecs")

    before = ecs.list_account_settings(name="containerInsights", effectiveSettings=True).get("settings", [])
    before_value = before[0]["value"] if before else "disabled"

    def _restore():
        try:
            ecs.delete_account_setting(name="containerInsights")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "InvalidParameterException"
                and "Referenced setting doesn't exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_restore)

    new_value = "disabled" if before_value != "disabled" else "enabled"
    put_resp = ecs.put_account_setting(name="containerInsights", value=new_value)["setting"]
    assert put_resp["name"] == "containerInsights", put_resp
    assert put_resp["value"] == new_value, put_resp

    after = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)["settings"]
    assert after and after[0]["value"] == new_value, after

    # Negative: value isn't one of the accepted tokens for this setting name.
    code, message = _error(lambda: ecs.put_account_setting(
        name="containerInsights", value="sim2real-not-a-real-value"
    ))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "Invalid setting 'value'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden write did not happen: the setting still reflects our valid new_value.
    still = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)["settings"]
    assert still and still[0]["value"] == new_value, still


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
