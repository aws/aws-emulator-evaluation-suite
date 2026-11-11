"""daemon-task-definition-register-describe-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "daemon-task-definition-register-describe-list"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterDaemonTaskDefinition creates an ACTIVE revision visible via Describe and List."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-daemon-td-")

    resp = ecs.register_daemon_task_definition(
        family=family,
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "cpu": 128,
                "memory": 256,
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn = resp["daemonTaskDefinitionArn"]
    assert td_arn.endswith(f"daemon-task-definition/{family}:1"), (
        f"expected ARN to end with 'daemon-task-definition/{family}:1', got {td_arn}"
    )
    ctx.on_cleanup(lambda: _delete_best_effort(ecs, td_arn))

    desc = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert desc["family"] == family, f"expected family {family!r}, got {desc['family']!r}"
    assert desc["status"] == "ACTIVE", f"expected status ACTIVE, got {desc['status']!r}"
    assert desc["revision"] == 1, f"expected revision 1, got {desc['revision']!r}"
    assert desc["containerDefinitions"][0]["name"] == "agent", (
        f"expected container name 'agent', got {desc['containerDefinitions'][0]['name']!r}"
    )

    # a second revision in the same family bumps the revision number
    resp2 = ecs.register_daemon_task_definition(
        family=family,
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "cpu": 128,
                "memory": 256,
                "essential": True,
                "command": ["sleep", "7200"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn_2 = resp2["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_best_effort(ecs, td_arn_2))
    desc2 = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn_2)["daemonTaskDefinition"]
    assert desc2["revision"] == 2, f"expected revision 2, got {desc2['revision']!r}"
    assert desc2["family"] == family, f"expected family {family!r}, got {desc2['family']!r}"

    # Real AWS rejects sort="LAST_REGISTERED" outright (InvalidParameterException: "Invalid
    # SortOrder LAST_REGISTERED encountered") — that value isn't a real SortOrder enum member.
    # It also rejects status="ALL" unless paired with a specific (undocumented-to-us) sort value
    # ("ALL status can only be used with LAST_REG..."). Neither revision here has been deleted,
    # so they're both still ACTIVE — the default (status omitted, i.e. ACTIVE-only) listing
    # already covers this assertion without needing ALL or a sort override at all.
    listed = ecs.list_daemon_task_definitions(familyPrefix=family)["daemonTaskDefinitions"]
    listed_arns = {d["arn"] for d in listed}
    assert td_arn in listed_arns, "revision 1 must be visible in ListDaemonTaskDefinitions"
    assert td_arn_2 in listed_arns, "revision 2 must be visible in ListDaemonTaskDefinitions"
    for d in listed:
        if d["arn"] in (td_arn, td_arn_2):
            assert d["status"] == "ACTIVE", f"expected ACTIVE for {d['arn']}, got {d['status']!r}"


# ===== helpers =====

def _delete_best_effort(ecs, td_arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
