"""create-encoder-configuration-bitrate-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-encoder-configuration-bitrate-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration rejects a bitrate above the 8,500,000 bps ceiling."""
    ivs = ctx.client("ivs-realtime")

    error = _client_error(
        lambda: ivs.create_encoder_configuration(
            name=ctx.unique_name("sim2real-enc-"),
            video={"bitrate": 8500001},
        )
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == (
        "CreateEncoderConfiguration.video.bitrate is required to have a maximum value of "
        "8500000.0, found 8500001.0"
    ), error

    # Positive control: the maximum allowed bitrate is accepted.
    created = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"),
        video={"bitrate": 8500000},
    )["encoderConfiguration"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=created["arn"]))
    assert created["video"]["bitrate"] == 8500000, created["video"]

    # Terminal assertion: an independent read confirms the accepted bitrate persisted,
    # not just the mutating call's own echo.
    fetched = ivs.get_encoder_configuration(arn=created["arn"])["encoderConfiguration"]
    assert fetched["video"]["bitrate"] == 8500000, fetched["video"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
