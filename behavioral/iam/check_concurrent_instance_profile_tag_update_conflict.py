"""concurrent-instance-profile-tag-update-conflict."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-instance-profile-tag-update-conflict"
GROUP = "concurrency"
SERVICES = ["iam"]

RACER_COUNT = 10


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing TagInstanceProfile calls with distinct keys either succeed or fail with
    ConcurrentModification, and the final tag set holds every tag reported as successful."""
    iam = ctx.client("iam")
    profile_name = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    racer_tags = [{"Key": f"racer-{i}", "Value": f"value-{i}"} for i in range(RACER_COUNT)]
    barrier = threading.Barrier(RACER_COUNT)

    def _racer(tag: dict):
        barrier.wait(timeout=10)
        iam.tag_instance_profile(InstanceProfileName=profile_name, Tags=[tag])
        return tag

    results = []
    with ThreadPoolExecutor(max_workers=RACER_COUNT) as ex:
        futures = [ex.submit(_racer, tag) for tag in racer_tags]
        for f in futures:
            results.append(_outcome(f))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) >= 1, f"expected at least one successful tag write, got results={results}"
    for _, code in failures:
        assert code == "ConcurrentModification", (
            f"expected only ConcurrentModification on losers, got {code!r} in {results}"
        )

    final_tags = _wait_for_tag_count(ctx, profile_name, expected_count=len(successes))
    final_by_key = {t["Key"]: t["Value"] for t in final_tags}
    for _, tag in successes:
        assert final_by_key.get(tag["Key"]) == tag["Value"], (
            f"tag {tag} reported successful but missing/wrong in final state {final_by_key}"
        )


def _outcome(future):
    from botocore.exceptions import ClientError

    try:
        return ("ok", future.result())
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


def _wait_for_tag_count(ctx, profile_name: str, expected_count: int, timeout_s: float = 20.0):
    import time

    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    tags = []
    while time.monotonic() < deadline:
        tags = iam.list_instance_profile_tags(InstanceProfileName=profile_name)["Tags"]
        if len(tags) >= expected_count:
            return tags
        time.sleep(0.5)
    raise TimeoutError(
        f"expected {expected_count} tags on {profile_name} within {timeout_s}s, "
        f"got {len(tags)}: {tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
