"""command-payload-binary-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "command-payload-binary-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A binary command payload (including null bytes and high-bit bytes) survives
    CreateCommand and GetCommand unchanged, proving there's no base64 re-encoding drift or
    text-mode mangling in the payload pipeline."""
    iot = ctx.client("iot")

    command_id = ctx.unique_name("sim2real-iot-cmd-")
    binary_payload = bytes(range(256)) + b"\x00\xff\x00\xff-tail-\xe2\x9c\x93-\x01\x02\x03"
    content_type = "application/octet-stream"

    iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        description="binary payload round-trip check",
        payload={"content": binary_payload, "contentType": content_type},
        tags=[{"Key": "sim2real", "Value": command_id}],
    )
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))

    got = iot.get_command(commandId=command_id)
    assert got["commandId"] == command_id, (command_id, got.get("commandId"))
    assert got["payload"]["content"] == binary_payload, (
        len(got["payload"]["content"]),
        len(binary_payload),
    )
    assert got["payload"]["contentType"] == content_type, (
        content_type,
        got["payload"]["contentType"],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
