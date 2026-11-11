"""notify-code-configuration-lookup-by-arn-and-rejects-malformed-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notify-code-configuration-lookup-by-arn-and-rejects-malformed-id"
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
    """GetNotifyCodeConfiguration resolves a configuration by id or ARN to one record, refuses
    a malformed id with ValidationException, and a deleted id with ResourceNotFoundException.
    """
    eum = ctx.client("endusermessaging")
    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=ctx.unique_name("sim2real-behav-eum-ccident-")
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))
    arn = config["notifyCodeConfigurationArn"]
    by_id = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    by_arn = eum.get_notify_code_configuration(notifyCodeConfigurationId=arn)["notifyCodeConfiguration"]
    assert by_id == by_arn, "lookups by id and by ARN must answer the same configuration"

    name = config["notifyCodeConfigurationName"]
    code, message = _error(lambda: eum.get_notify_code_configuration(notifyCodeConfigurationId=name))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == f"invalid notify code configuration ID format: {name}", f"unexpected message {message!r}"

    eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid)
    code, message = _error(lambda: eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == (
        f'Resource not found - ResourceType="notify-code-configuration" ResourceId="{ccid}"'
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
