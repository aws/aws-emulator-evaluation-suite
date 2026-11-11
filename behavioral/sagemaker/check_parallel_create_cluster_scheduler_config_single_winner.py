"""parallel-create-cluster-scheduler-config-single-winner."""
from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parallel-create-cluster-scheduler-config-single-winner"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateClusterSchedulerConfig calls on a nonexistent ClusterArn both fail.

    Each racer gets ValidationException 'Specified cluster not found', and
    ListClusterSchedulerConfigs shows no config persisted under the name.
    """
    sm = ctx.client("sagemaker")
    cluster_arn = _synthetic_cluster_arn(ctx)
    name = ctx.unique_name("sim2real-csc-")

    def _create():
        return sm.create_cluster_scheduler_config(
            Name=name,
            ClusterArn=cluster_arn,
            SchedulerConfig={},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        outcomes = []
        for fut in futures:
            try:
                outcomes.append(("ok", fut.result()))
            except ClientError as exc:
                outcomes.append(("error", exc))

    successes = [resp for kind, resp in outcomes if kind == "ok"]
    failures = [exc for kind, exc in outcomes if kind == "error"]

    # Defensive: if a target (e.g. a weaker emulator under fidelity grading) lets a
    # racer through despite the nonexistent cluster, clean up what it persisted.
    for resp in successes:
        config_id = resp["ClusterSchedulerConfigId"]
        ctx.on_cleanup(
            lambda cid=config_id: sm.delete_cluster_scheduler_config(
                ClusterSchedulerConfigId=cid
            )
        )

    codes = [exc.response["Error"]["Code"] for exc in failures]
    assert len(failures) == 2 and not successes, (
        f"expected both concurrent racers against a nonexistent cluster to be "
        f"rejected outright, got {len(successes)} success(es) and {len(failures)} "
        f"failure(s) (codes={codes})"
    )
    assert codes == ["ValidationException", "ValidationException"], (
        f"expected ValidationException on every racer (cluster-existence validated "
        f"before Name-conflict arbitration, race-proof), got {codes}"
    )
    messages = [exc.response["Error"].get("Message", "") for exc in failures]
    assert messages == ["Specified cluster not found", "Specified cluster not found"], messages

    # Effect: a validation-rejected create never persists anything under this name --
    # an independent read, at a different operation than the mutating call.
    summaries = sm.list_cluster_scheduler_configs(NameContains=name)[
        "ClusterSchedulerConfigSummaries"
    ]
    matching = [s for s in summaries if s["Name"] == name]
    assert matching == [], f"expected no persisted config for a rejected name, found {matching}"


def _synthetic_cluster_arn(ctx) -> str:
    """A syntactically valid but nonexistent HyperPod cluster ARN."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cluster_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{cluster_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
