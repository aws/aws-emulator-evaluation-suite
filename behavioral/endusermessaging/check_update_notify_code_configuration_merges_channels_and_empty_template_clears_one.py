"""update-notify-code-configuration-merges-channels-and-empty-template-clears-one."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-notify-code-configuration-merges-channels-and-empty-template-clears-one"
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
    """Updating one channel keeps the others; an empty text template removes the text channel
    while the voice channel and its settings stay as stored.
    """
    eum = ctx.client("endusermessaging")
    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=ctx.unique_name("sim2real-behav-eum-chan-"),
        channelParameters={"text": {"inlineTemplateBody": "Code {{code}}"}}
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    eum.update_notify_code_configuration(notifyCodeConfigurationId=ccid, channelParameters={
        "voice": {"inlineTemplateBody": "Your code is {{code}}", "languageCode": "en-US", "voiceId": "Joanna"}})
    merged = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert merged["channelParameters"] == {
        "text": {"inlineTemplateBody": "Code {{code}}"},
        "voice": {"inlineTemplateBody": "Your code is {{code}}", "languageCode": "en-US", "voiceId": "Joanna"},
    }, f"after adding voice: {merged['channelParameters']!r}"

    eum.update_notify_code_configuration(notifyCodeConfigurationId=ccid,
                                         channelParameters={"text": {"inlineTemplateBody": ""}})
    cleared = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert cleared["channelParameters"] == {
        "voice": {"inlineTemplateBody": "Your code is {{code}}", "languageCode": "en-US", "voiceId": "Joanna"},
    }, f"after clearing text: {cleared['channelParameters']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
