"""encoder-configuration-custom-video-settings-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-custom-video-settings-persist"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Explicit, non-default Video settings passed to CreateEncoderConfiguration are
    stored and returned verbatim by GetEncoderConfiguration."""
    client = ctx.client("ivs-realtime")
    video = {"width": 640, "height": 360, "framerate": 24.0, "bitrate": 900000}
    created = client.create_encoder_configuration(
        name=ctx.unique_name("sim2real-encoder"),
        video=video,
        tags={"sim2real": "true"},
    )["encoderConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: client.delete_encoder_configuration(arn=arn))

    cv = created["video"]
    assert cv["width"] == 640, f"expected width 640, got {cv['width']}"
    assert cv["height"] == 360, f"expected height 360, got {cv['height']}"
    assert cv["framerate"] == 24.0, f"expected framerate 24.0, got {cv['framerate']}"
    assert cv["bitrate"] == 900000, f"expected bitrate 900000, got {cv['bitrate']}"

    fetched = client.get_encoder_configuration(arn=arn)["encoderConfiguration"]["video"]
    assert fetched["width"] == 640, f"expected fetched width 640, got {fetched['width']}"
    assert fetched["height"] == 360, f"expected fetched height 360, got {fetched['height']}"
    assert fetched["framerate"] == 24.0, (
        f"expected fetched framerate 24.0, got {fetched['framerate']}"
    )
    assert fetched["bitrate"] == 900000, f"expected fetched bitrate 900000, got {fetched['bitrate']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
