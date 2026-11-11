"""notify-code-configuration-deletion-protection-blocks-then-allows-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notify-code-configuration-deletion-protection-blocks-then-allows-delete"
GROUP = 'notify-code-configurations'
SERVICES = ['endusermessaging']

_CHANNEL_PARAMETERS = {"text": {"inlineTemplateBody": "Your code is {{code}}"}}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deletion-protected notify code configuration refuses delete with ConflictException;
    turning protection off through UpdateNotifyCodeConfiguration is what makes it succeed.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-ccdp-")

    created = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=name,
        codeConfigurationParameters={"codeType": "NUMERIC", "codeLength": 6,
                                      "validityPeriodMinutes": 10, "maxAttempts": 3},
        channelParameters=_CHANNEL_PARAMETERS,
        deletionProtectionEnabled=True,
    )["notifyCodeConfiguration"]
    ccid = created["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))
    assert created["deletionProtectionEnabled"] is True, (
        f"expected deletionProtectionEnabled True, got {created['deletionProtectionEnabled']!r}"
    )

    code, message = _error(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid))
    assert code == "ConflictException", f"expected ConflictException while protected, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="DELETION_PROTECTION_ENABLED" ResourceType="notify-code-configuration"'
    ), f"unexpected message {message!r}"

    still_there = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)
    assert still_there["notifyCodeConfiguration"]["notifyCodeConfigurationId"] == ccid, (
        "the configuration should still exist after the refused delete"
    )

    updated = eum.update_notify_code_configuration(
        notifyCodeConfigurationId=ccid, deletionProtectionEnabled=False
    )["notifyCodeConfiguration"]
    assert updated["deletionProtectionEnabled"] is False, (
        f"expected deletionProtectionEnabled False after update, got {updated['deletionProtectionEnabled']!r}"
    )

    eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid)
    code, message = _error(lambda: eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid))
    assert code == "ResourceNotFoundException", (
        f"expected the configuration to be gone once protection was off, got {code}: {message!r}"
    )
    assert message == (
        f'Resource not found - ResourceType="notify-code-configuration" ResourceId="{ccid}"'
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
