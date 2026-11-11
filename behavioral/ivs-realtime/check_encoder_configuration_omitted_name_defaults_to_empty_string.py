"""encoder-configuration-omitted-name-defaults-to-empty-string."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-omitted-name-defaults-to-empty-string"
GROUP = "encoder-configuration"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration with no `name` field creates a resource whose name is
    the empty string (name has length min:0), not a generated placeholder name."""
    ivsrt = ctx.client("ivs-realtime")
    created = ivsrt.create_encoder_configuration(tags={"sim2real": CHECK})["encoderConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=created["arn"]))

    created_name = created.get("name", "")
    assert created_name == "", f"expected omitted name to default to '', got {created_name!r}"

    fetched = ivsrt.get_encoder_configuration(arn=created["arn"])["encoderConfiguration"]
    fetched_name = fetched.get("name", "")
    assert fetched_name == "", f"expected fetched name to default to '', got {fetched_name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
