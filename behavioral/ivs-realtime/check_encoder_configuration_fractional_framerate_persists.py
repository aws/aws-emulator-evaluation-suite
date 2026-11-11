"""encoder-configuration-fractional-framerate-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-fractional-framerate-persists"
GROUP = "encoder-configuration"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fractional framerate (29.97, a real broadcast cadence) passed to
    CreateEncoderConfiguration is preserved exactly by GetEncoderConfiguration, not
    rounded to a nearby integer."""
    ivsrt = ctx.client("ivs-realtime")
    created = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-ivsrt-enc-"),
        video={"width": 1280, "height": 720, "framerate": 29.97, "bitrate": 2000000},
        tags={"purpose": "sim2real"},
    )["encoderConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=created["arn"]))

    assert abs(created["video"]["framerate"] - 29.97) < 1e-6, created["video"]["framerate"]

    fetched = ivsrt.get_encoder_configuration(arn=created["arn"])["encoderConfiguration"]
    assert abs(fetched["video"]["framerate"] - 29.97) < 1e-6, fetched["video"]["framerate"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
