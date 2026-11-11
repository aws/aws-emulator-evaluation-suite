"""create-cluster-scheduler-config-duplicate-name-conflict-rejected."""
from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-cluster-scheduler-config-duplicate-name-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateClusterSchedulerConfig calls with one Name against a nonexistent ClusterArn
    both fail with ValidationException and the identical exact message, and no config is listed under
    that name: the cluster-existence check is not racy."""
    sm = ctx.client("sagemaker")

    # Positive control: the account/credentials are otherwise healthy for this service.
    sm.list_cluster_scheduler_configs(NameContains="sim2real-behav-csc-positive-control-probe")

    cluster_arn = _fake_cluster_arn(ctx)
    name = ctx.unique_name("sim2real-behav-csc-")

    def _create():
        return sm.create_cluster_scheduler_config(Name=name, ClusterArn=cluster_arn, SchedulerConfig={})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        results = []
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001 - classify below
                results.append(("error", exc))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [_client_error_code(r) for kind, r in results if kind == "error"]
    messages = [_client_error_message(r) for kind, r in results if kind == "error"]

    assert not successes, (
        f"CreateClusterSchedulerConfig against a nonexistent ClusterArn must never succeed, "
        f"got {len(successes)} success(es) among results={results!r}"
    )
    assert len(errors) == 2, f"expected both concurrent racers to fail, got results={results!r}"
    assert errors == ["ValidationException", "ValidationException"], (
        f"expected both racers rejected identically with ValidationException (the cluster-"
        f"existence gate must not be racy), got {errors!r}"
    )
    expected_message = "Specified cluster not found"
    assert messages == [expected_message, expected_message], (
        f"expected both racers rejected with {expected_message!r}, got {messages!r}"
    )

    # Effect absent: no config was ever persisted under a name that never won a race.
    listing = sm.list_cluster_scheduler_configs(NameContains=name)["ClusterSchedulerConfigSummaries"]
    assert listing == [], f"expected no persisted config for {name!r}, got {listing!r}"


def _client_error_message(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message")
    raise exc


def _client_error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    raise exc


def _fake_cluster_arn(ctx):
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    cluster_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{cluster_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
