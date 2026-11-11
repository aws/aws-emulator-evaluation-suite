"""notify-code-template-must-contain-code-placeholder."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notify-code-template-must-contain-code-placeholder"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A text or voice template without the {{code}} placeholder is refused on create and on
    update with ValidationException; a template carrying it is stored.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-tmpl-")
    code, message = _error(lambda: eum.create_notify_code_configuration(
        notifyCodeConfigurationName=name,
        channelParameters={"text": {"inlineTemplateBody": "Your sign-in code"}}))
    assert code == "ValidationException", f"create: expected ValidationException, got {code}: {message!r}"
    assert message == "template body must contain {{code}} placeholder", f"create: unexpected message {message!r}"

    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=name,
        channelParameters={"text": {"inlineTemplateBody": "Your sign-in code is {{code}}"}},
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: eum.update_notify_code_configuration(
        notifyCodeConfigurationId=ccid,
        channelParameters={"voice": {"inlineTemplateBody": "Your code follows"}}))
    assert code == "ValidationException", f"update: expected ValidationException, got {code}: {message!r}"
    assert message == "template body must contain {{code}} placeholder", f"update: unexpected message {message!r}"

    got = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert got["channelParameters"] == {"text": {"inlineTemplateBody": "Your sign-in code is {{code}}"}}, (
        f"the refused update changed the channels: {got['channelParameters']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
