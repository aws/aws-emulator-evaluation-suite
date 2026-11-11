"""overly-permissive-scheduled-action-invalid-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "overly-permissive-scheduled-action-invalid-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateScheduledAction with an ActionType outside the enum is ValidationException, while a
    valid ActionType with the same nonexistent ActionID is ResourceNotFoundException: input
    validation runs before the ActionID lookup."""
    client = ctx.client("opensearch")
    domain_name, _ = _create_minimal_domain(ctx)
    bogus_action_id = ctx.unique_name("sim2real-action-")

    invalid_code, invalid_message = _error(
        lambda: client.update_scheduled_action(
            DomainName=domain_name,
            ActionID=bogus_action_id,
            ActionType="NOT_A_REAL_ACTION_TYPE",
            ScheduleAt="NOW",
        )
    )
    assert invalid_code == "ValidationException", (
        f"expected ValidationException for an out-of-range ActionType, got {invalid_code!r}"
    )
    expected = (
        "1 validation error detected: Value 'NOT_A_REAL_ACTION_TYPE' at 'actionType' failed to "
        "satisfy constraint: Member must satisfy enum value set: "
        "[JVM_YOUNG_GEN_TUNING, SERVICE_SOFTWARE_UPDATE, JVM_HEAP_SIZE_TUNING]"
    )
    assert invalid_message == expected, f"expected message {expected!r}, got {invalid_message!r}"

    # Positive control: same DomainName/ActionID, but a *valid* ActionType. This must clear
    # input validation and fail for the different, later-stage reason (ActionID not found).
    control_code, control_message = _error(
        lambda: client.update_scheduled_action(
            DomainName=domain_name,
            ActionID=bogus_action_id,
            ActionType="SERVICE_SOFTWARE_UPDATE",
            ScheduleAt="NOW",
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException once ActionType is valid (only ActionID is now "
        f"bogus), got {control_code!r}"
    )
    expected = "ReleaseVersion does not applies for this domain or release does not exist"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"

    # Terminal, independent read: neither rejected attempt created or mutated a scheduled
    # action for this id.
    existing = client.list_scheduled_actions(DomainName=domain_name)["ScheduledActions"]
    assert all(a["Id"] != bogus_action_id for a in existing), (
        f"a scheduled action for the bogus id leaked into the domain's list: {existing!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_minimal_domain(ctx):
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-osd-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    client.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": account_id},
                        "Action": "es:*",
                        "Resource": "*",
                    }
                ],
            }
        ),
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    deadline = time.monotonic() + 1800
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return name, status
        time.sleep(2)
    raise AssertionError(f"domain {name} did not become active within budget: {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
