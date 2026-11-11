"""create-encoder-configuration-video-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-encoder-configuration-video-defaults"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration without a video block defaults to 1280x720 @30fps, 2.5Mbps."""
    ivs = ctx.client("ivs-realtime")
    created = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"),
        tags={"sim2real-check": CHECK},
    )["encoderConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=arn))

    video = created["video"]
    assert video["width"] == 1280, video
    assert video["height"] == 720, video
    assert video["framerate"] == 30, video
    assert video["bitrate"] == 2500000, video

    fetched = ivs.get_encoder_configuration(arn=arn)["encoderConfiguration"]["video"]
    assert fetched == video, fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
