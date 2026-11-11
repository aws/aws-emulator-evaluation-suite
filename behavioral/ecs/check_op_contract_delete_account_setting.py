"""op-contract-deleteAccountSetting."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteAccountSetting"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """DeleteAccountSetting removes a per-principal setting and rejects a malformed principalArn."""
    ecs = ctx.client("ecs")

    put = ecs.put_account_setting(name="containerInsights", value="enhanced")
    principal_arn = put["setting"]["principalArn"]
    ctx.on_cleanup(lambda: _safe_delete(ecs, principal_arn))
    assert put["setting"]["value"] == "enhanced", put["setting"]

    settings = ecs.list_account_settings(name="containerInsights", principalArn=principal_arn)["settings"]
    assert any(s["value"] == "enhanced" for s in settings), (
        f"expected a setting with value 'enhanced' for {principal_arn}, got {settings}"
    )

    ecs.delete_account_setting(name="containerInsights", principalArn=principal_arn)

    remaining = ecs.list_account_settings(
        name="containerInsights", principalArn=principal_arn, effectiveSettings=False
    )["settings"]
    assert not any(s.get("principalArn") == principal_arn and s["value"] == "enhanced" for s in remaining), (
        f"expected the deleted override for {principal_arn} to be gone, still saw {remaining}"
    )

    err, message = _error(
        lambda: ecs.delete_account_setting(name="containerInsights", principalArn="not-a-valid-arn")
    )
    assert err == "InvalidParameterException", f"expected InvalidParameterException, got {err}"
    expected_message = 'Invalid PrincipalArn: not-a-valid-arn'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete(ecs, principal_arn):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_account_setting(name="containerInsights", principalArn=principal_arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidParameterException"
            and "Referenced setting doesn't exist" in err.get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
