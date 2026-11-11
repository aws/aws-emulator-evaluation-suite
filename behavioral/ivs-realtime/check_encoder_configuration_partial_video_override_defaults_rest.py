"""encoder-configuration-partial-video-override-defaults-rest."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-partial-video-override-defaults-rest"
GROUP = "encoder-configuration"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Specifying only `bitrate` in the video block leaves width/height/framerate at
    their documented defaults (1280/720/30), rather than zeroing them out or inheriting
    some other value."""
    ivsrt = ctx.client("ivs-realtime")
    created = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-ivsrt-enc-"),
        video={"bitrate": 1234567},
        tags={"sim2real-check": CHECK},
    )["encoderConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=created["arn"]))

    video = created["video"]
    assert video["bitrate"] == 1234567, video
    assert video["width"] == 1280, video
    assert video["height"] == 720, video
    assert video["framerate"] == 30, video

    fetched = ivsrt.get_encoder_configuration(arn=created["arn"])["encoderConfiguration"]
    assert fetched["video"] == video, fetched["video"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
