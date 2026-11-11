"""server-side-default-host-key-managed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-side-default-host-key-managed"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A server created without ImportHostKey has a HostKeyFingerprint, ListHostKeys returns a key of a known SSH
    type with that fingerprint, and DescribeHostKey reports the same fingerprint."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    described = transfer.describe_server(ServerId=server_id)["Server"]
    fingerprint = described.get("HostKeyFingerprint")
    assert fingerprint, "expected a server-managed HostKeyFingerprint without any ImportHostKey call"

    host_keys = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    matching = [hk for hk in host_keys if hk.get("Fingerprint") == fingerprint]
    assert matching, (
        f"none of the listed host keys {host_keys!r} match the server's active "
        f"fingerprint {fingerprint!r} -- the auto-generated default key is not exposed "
        "as a queryable resource"
    )

    known_types = {"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
    assert matching[0]["Type"] in known_types, f"unexpected host key type {matching[0]['Type']!r}"

    described_key = transfer.describe_host_key(
        ServerId=server_id, HostKeyId=matching[0]["HostKeyId"]
    )["HostKey"]
    assert described_key["HostKeyFingerprint"] == fingerprint, (
        "DescribeHostKey must report the same fingerprint as DescribeServer and ListHostKeys "
        "for the system-managed default key"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
