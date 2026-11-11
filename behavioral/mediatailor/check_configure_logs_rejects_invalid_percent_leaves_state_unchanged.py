"""configure-logs-rejects-invalid-percent-leaves-state-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configure-logs-rejects-invalid-percent-leaves-state-unchanged"
GROUP = 'playback-configuration-logging'
SERVICES = ['mediatailor']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A PercentEnabled above 100 is refused, and the rejected call leaves the previously
    configured logging percentage untouched rather than partially applying it."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-pc-")

    mt.put_playback_configuration(
        Name=name,
        VideoContentSourceUrl="https://example.com/vod",
        AdDecisionServerUrl="https://example.com/ads",
    )
    ctx.on_cleanup(lambda: mt.delete_playback_configuration(Name=name))

    mt.configure_logs_for_playback_configuration(
        PlaybackConfigurationName=name, PercentEnabled=50,
        EnabledLoggingStrategies=["VENDED_LOGS"],
    )

    before = mt.get_playback_configuration(Name=name)["LogConfiguration"]
    assert before["PercentEnabled"] == 50, f"expected 50 before the rejected call, got {before!r}"

    code, message = _error(lambda: mt.configure_logs_for_playback_configuration(
        PlaybackConfigurationName=name, PercentEnabled=150,
        EnabledLoggingStrategies=["VENDED_LOGS"],
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == "PercentEnabled must not exceed 100", f"unexpected message {message!r}"

    after = mt.get_playback_configuration(Name=name)["LogConfiguration"]
    assert after["PercentEnabled"] == 50, (
        f"the rejected call changed PercentEnabled to {after['PercentEnabled']!r}, expected it to stay 50"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
