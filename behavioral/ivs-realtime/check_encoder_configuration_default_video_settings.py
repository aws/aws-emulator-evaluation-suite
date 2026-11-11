"""encoder-configuration-default-video-settings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-default-video-settings"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration with no Video block applies the documented defaults:
    1280x720, 30fps, 2,500,000 bps -- not zeros or some other placeholder."""
    client = ctx.client("ivs-realtime")
    created = client.create_encoder_configuration(
        name=ctx.unique_name("sim2real-encoder"), tags={"sim2real": "audit"}
    )["encoderConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: client.delete_encoder_configuration(arn=arn))

    fetched = client.get_encoder_configuration(arn=arn)["encoderConfiguration"]
    video = fetched["video"]
    assert video["width"] == 1280, video
    assert video["height"] == 720, video
    assert video["framerate"] == 30, video
    assert video["bitrate"] == 2500000, video


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
