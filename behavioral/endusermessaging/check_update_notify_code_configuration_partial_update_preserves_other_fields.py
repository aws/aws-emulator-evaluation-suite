"""update-notify-code-configuration-partial-update-preserves-other-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-notify-code-configuration-partial-update-preserves-other-fields"
GROUP = 'notify-code-configurations'
SERVICES = ['endusermessaging']

_CHANNEL_PARAMETERS = {"text": {"inlineTemplateBody": "Your code is {{code}}"}}


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
    """UpdateNotifyCodeConfiguration changes only the members the caller names; an omitted
    codeConfigurationParameters member keeps its current value rather than resetting.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-ccupdate-")

    created = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=name,
        codeConfigurationParameters={"codeType": "NUMERIC", "codeLength": 6,
                                      "validityPeriodMinutes": 15, "maxAttempts": 3},
        channelParameters=_CHANNEL_PARAMETERS,
    )["notifyCodeConfiguration"]
    ccid = created["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    updated = eum.update_notify_code_configuration(
        notifyCodeConfigurationId=ccid,
        codeConfigurationParameters={"codeLength": 8},
    )["notifyCodeConfiguration"]
    params = updated["codeConfigurationParameters"]
    assert params["codeLength"] == 8, f"expected codeLength updated to 8, got {params['codeLength']!r}"
    assert params["codeType"] == "NUMERIC", f"codeType should be preserved, got {params['codeType']!r}"
    assert params["validityPeriodMinutes"] == 15, (
        f"validityPeriodMinutes should be preserved, got {params['validityPeriodMinutes']!r}"
    )
    assert params["maxAttempts"] == 3, f"maxAttempts should be preserved, got {params['maxAttempts']!r}"

    fetched = eum.get_notify_code_configuration(notifyCodeConfigurationId=ccid)["notifyCodeConfiguration"]
    assert fetched["codeConfigurationParameters"] == params, (
        "a later Get disagreed with Update's own response: "
        f"{fetched['codeConfigurationParameters']!r} != {params!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
