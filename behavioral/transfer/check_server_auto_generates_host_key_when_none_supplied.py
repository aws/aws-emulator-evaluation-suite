"""server-auto-generates-host-key-when-none-supplied."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-auto-generates-host-key-when-none-supplied"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A server created without ImportHostKey gets an auto-generated host key that ListHostKeys
    and DescribeHostKey expose, with a fingerprint matching the server's HostKeyFingerprint."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    described_server = transfer.describe_server(ServerId=server_id)["Server"]
    server_fingerprint = described_server.get("HostKeyFingerprint")
    assert server_fingerprint, "a freshly created server has no active HostKeyFingerprint at all"

    host_keys = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    assert host_keys, (
        "ListHostKeys returned no entries for a server that was never given an "
        "explicit ImportHostKey call -- the auto-generated default host key is not "
        "exposed as a queryable resource"
    )

    matching = [hk for hk in host_keys if hk.get("Fingerprint") == server_fingerprint]
    assert matching, (
        f"none of the listed host keys {host_keys!r} match the server's active "
        f"fingerprint {server_fingerprint!r}"
    )

    described_key = transfer.describe_host_key(
        ServerId=server_id, HostKeyId=matching[0]["HostKeyId"]
    )["HostKey"]
    assert described_key["HostKeyFingerprint"] == server_fingerprint, (
        f"DescribeHostKey returned fingerprint {described_key['HostKeyFingerprint']!r} for "
        f"host key {matching[0]['HostKeyId']!r}, expected it to match the server's active "
        f"fingerprint {server_fingerprint!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
