"""update-notify-code-configuration-with-no-fields-changes-nothing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-notify-code-configuration-with-no-fields-changes-nothing"
GROUP = "notify-code-configurations"
SERVICES = ["endusermessaging"]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotifyCodeConfiguration naming no member succeeds and answers the stored
    configuration unchanged, as a later Get confirms.
    """
    eum = ctx.client("endusermessaging")
    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=ctx.unique_name("sim2real-behav-eum-noop-"),
        codeConfigurationParameters={"codeType": "NUMERIC", "codeLength": 6,
                                     "validityPeriodMinutes": 5, "maxAttempts": 3},
        channelParameters={"text": {"inlineTemplateBody": "Code {{code}}"}}
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    answered = eum.update_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    got = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    for source, body in (("update", answered), ("get", got)):
        assert body["notifyCodeConfigurationName"] == config["notifyCodeConfigurationName"], (
            f"{source}: name {body['notifyCodeConfigurationName']!r}"
        )
        assert body["codeConfigurationParameters"] == {"codeType": "NUMERIC", "codeLength": 6,
                                                       "validityPeriodMinutes": 5, "maxAttempts": 3}, (
            f"{source}: code parameters {body['codeConfigurationParameters']!r}"
        )
        assert body["channelParameters"] == {"text": {"inlineTemplateBody": "Code {{code}}"}}, (
            f"{source}: channels {body['channelParameters']!r}"
        )
        assert body["deletionProtectionEnabled"] is False, f"{source}: protection changed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
