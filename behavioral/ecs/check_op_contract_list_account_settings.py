"""op-contract-listAccountSettings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listAccountSettings"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """ListAccountSettings surfaces a set value and doesn't leak it under an unrelated principal."""
    ecs = ctx.client("ecs")

    put = ecs.put_account_setting(name="containerInsights", value="enhanced")
    principal_arn = put["setting"]["principalArn"]
    ctx.on_cleanup(lambda: ecs.delete_account_setting(name="containerInsights", principalArn=principal_arn))

    resp = ecs.list_account_settings(name="containerInsights", value="enhanced", principalArn=principal_arn)
    assert len(resp["settings"]) >= 1, f"expected at least one setting, got {resp['settings']}"
    assert all(s["value"] == "enhanced" for s in resp["settings"]), (
        f"expected every returned setting to have value 'enhanced': {resp['settings']}"
    )
    assert any(s["principalArn"] == principal_arn for s in resp["settings"]), (
        f"expected {principal_arn} among returned principals: "
        f"{[s.get('principalArn') for s in resp['settings']]}"
    )

    # A principalArn scoped to a fabricated placeholder account (123456789012) never reaches the
    # "does this principal have a containerInsights setting" check: the account mismatch trips
    # ARN/authorization validation on a DIFFERENT axis than the scoping behavior this check means
    # to exercise. Use the CALLER's own account so the only thing distinguishing it from
    # `principal_arn` is the principal itself. A synthesized "user/<made-up-name>" ARN isn't
    # reliably accepted, though: real AWS's PrincipalArn validation for ListAccountSettings
    # rejects it outright ("Invalid PrincipalArn"). The account root ARN is always a
    # structurally valid principal reference, so use that instead -- deriving the partition
    # from the real `principal_arn` (rather than hardcoding "aws") keeps it correct in
    # non-commercial partitions too. On real AWS, though, querying settings scoped to ANY
    # principal other than the caller itself (even the account root, even with
    # ecs:ListAccountSettings permission) is rejected outright with InvalidParameterException
    # ("Only the root user can view or modify the account settings for another user") unless
    # the caller itself is the account's root user -- it doesn't silently scope the query down
    # to an empty result. That outright rejection is itself the no-leak guarantee this check
    # means to exercise: an unrelated principal's settings are never returned, because the
    # call never succeeds for a non-root caller in the first place.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    partition = principal_arn.split(":")[1]
    other_account_arn = f"arn:{partition}:iam::{account_id}:root"
    err, message = _error(
        lambda: ecs.list_account_settings(name="containerInsights", principalArn=other_account_arn)
    )
    assert err == "InvalidParameterException", (
        f"expected InvalidParameterException (only root may query another principal's "
        f"settings), got {err}"
    )
    expected_message = 'Only the root user can view or modify the account settings for another user. You do not need to specify a principalArn value to change your own account settings.'
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
