"""concurrent-create-namespace-same-name-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-namespace-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateDataLakeNamespace calls for the same instance/name race: despite the
    operation being a PUT, duplicate names are a conflict (not an idempotent overwrite),
    exactly one caller gets a 200 and every other caller gets ConflictException."""
    # AWS Supply Chain (CreateInstance) is region-pinned: real AWS answers ValidationException
    # ("Amazon Connect Decisions is not supported in ...") outside us-east-1.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _dl_name(ctx, "race")
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )

    racer_count = 6

    def _racer(i):
        try:
            sc.create_data_lake_namespace(
                instanceId=instance_id, name=ns_name, description=f"racer-{i}",
                tags={"sim2real:managed": "true"},
            )
            return ("ok", None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    conflicts = [r for r in results if r[1] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(conflicts) == racer_count - 1, f"expected the rest to be ConflictException: {results}"

    final = sc.get_data_lake_namespace(instanceId=instance_id, name=ns_name)["namespace"]
    assert final["name"] == ns_name, f"expected namespace {ns_name!r}, got {final['name']!r}"


def _dl_name(ctx, kind):
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check",
        tags={"sim2real:managed": "true"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
