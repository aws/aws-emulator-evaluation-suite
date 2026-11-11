"""disassociate-kms-key-without-association-is-a-no-op."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-kms-key-without-association-is-a-no-op"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateKmsKey on a log group that never had a key succeeds as a no-op, and the group
    still has no kmsKeyId afterwards.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-no-kms-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    described = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]
    assert "kmsKeyId" not in described

    # AWS accepts this call silently rather than raising ResourceNotFoundException.
    logs.disassociate_kms_key(logGroupName=group_name)

    described_after = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]
    assert "kmsKeyId" not in described_after, described_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
