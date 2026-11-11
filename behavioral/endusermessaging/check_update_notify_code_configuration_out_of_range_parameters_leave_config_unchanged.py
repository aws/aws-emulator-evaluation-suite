"""update-notify-code-configuration-out-of-range-parameters-leave-config-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-notify-code-configuration-out-of-range-parameters-leave-config-unchanged"
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
    """An update with codeLength above 8 or validityPeriodMinutes above 60 is refused with
    ValidationException naming the member, and the stored parameters are kept.
    """
    eum = ctx.client("endusermessaging")
    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=ctx.unique_name("sim2real-behav-eum-range-"),
        codeConfigurationParameters={"codeType": "NUMERIC", "codeLength": 6,
                                     "validityPeriodMinutes": 10, "maxAttempts": 3}
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    for member, value, bounds in (("codeLength", 9, "4 and 8"), ("validityPeriodMinutes", 61, "1 and 60")):
        code, message = _error(lambda: eum.update_notify_code_configuration(
            notifyCodeConfigurationId=ccid, codeConfigurationParameters={member: value}))
        assert code == "ValidationException", f"{member}: expected ValidationException, got {code}: {message!r}"
        assert message == (
            f"1 validation error detected. Value at '/codeConfigurationParameters/{member}' failed to "
            f"satisfy constraint: Member must be between {bounds}, inclusive"
        ), f"{member}: unexpected message {message!r}"

    got = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert got["codeConfigurationParameters"] == {"codeType": "NUMERIC", "codeLength": 6,
                                                  "validityPeriodMinutes": 10, "maxAttempts": 3}, (
        f"refused updates changed the parameters: {got['codeConfigurationParameters']!r}"
    )

    eum.update_notify_code_configuration(notifyCodeConfigurationId=ccid,
                                         codeConfigurationParameters={"codeLength": 8})
    got = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert got["codeConfigurationParameters"]["codeLength"] == 8, "positive control: codeLength 8 applies"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
