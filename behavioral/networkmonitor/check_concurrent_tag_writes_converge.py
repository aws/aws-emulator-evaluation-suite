"""concurrent-tag-writes-converge."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-tag-writes-converge"
GROUP = "concurrency"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls, each adding a different tag key to one monitor, lose no key:
    every key is present in the monitor's final tags."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    monitor_arn = nm.create_monitor(monitorName=name, aggregationPeriod=30)["monitorArn"]
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    writers = 8
    keys = [f"key{i}" for i in range(writers)]

    def _write(key):
        nm.tag_resource(resourceArn=monitor_arn, tags={key: "1"})
        return key

    with ThreadPoolExecutor(max_workers=writers) as pool:
        futures = [pool.submit(_write, k) for k in keys]
        for f in as_completed(futures):
            f.result()  # surface any exception immediately

    final_tags = nm.list_tags_for_resource(resourceArn=monitor_arn)["tags"]
    missing = [k for k in keys if final_tags.get(k) != "1"]
    assert not missing, f"concurrent non-conflicting tag writes lost keys: {missing} (final={final_tags})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
