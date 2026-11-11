"""configuration-description-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-description-empty-vs-absent-preserved"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfiguration returns no Description for a configuration created without one or with an
    empty string, and returns a non-empty Description verbatim."""
    kafka = ctx.client("kafka")
    props = b"auto.create.topics.enable=true\n"

    name_absent = ctx.unique_name("sim2real-behav-cfg-absent-")
    arn_absent = kafka.create_configuration(Name=name_absent, ServerProperties=props)["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn_absent))

    described_absent = kafka.describe_configuration(Arn=arn_absent)
    assert "Description" not in described_absent, (
        f"DescribeConfiguration fabricated a Description for a configuration created "
        f"without one: {described_absent.get('Description')!r}"
    )
    assert described_absent["Name"] == name_absent

    name_present = ctx.unique_name("sim2real-behav-cfg-present-")
    description_text = "sim2real behavioral description"
    arn_present = kafka.create_configuration(
        Name=name_present, Description=description_text, ServerProperties=props
    )["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn_present))

    described_present = kafka.describe_configuration(Arn=arn_present)
    assert described_present.get("Description") == description_text, (
        f"DescribeConfiguration did not preserve the Description verbatim: "
        f"expected {description_text!r}, got {described_present.get('Description')!r}"
    )
    assert described_present["Name"] == name_present

    name_empty = ctx.unique_name("sim2real-behav-cfg-empty-")
    arn_empty = kafka.create_configuration(
        Name=name_empty, Description="", ServerProperties=props
    )["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn_empty))

    described_empty = kafka.describe_configuration(Arn=arn_empty)
    assert "Description" not in described_empty, (
        f"DescribeConfiguration did not normalize an explicit empty Description to "
        f"absent: got {described_empty.get('Description')!r}"
    )
    assert described_empty["Name"] == name_empty


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
