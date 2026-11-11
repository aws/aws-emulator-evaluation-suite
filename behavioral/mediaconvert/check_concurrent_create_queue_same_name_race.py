"""concurrent-create-queue-same-name-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-queue-same-name-race"
GROUP = "concurrency"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent CreateQueue calls with the same Name all succeed and return the same queue ARN:
    CreateQueue is idempotent on Name, and GetQueue and ListQueues show exactly one queue of that name."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-queue-race-")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=name))

    racers = 8

    def attempt(_i):
        return mc.create_queue(Name=name, Tags={"sim2real-check": CHECK})["Queue"]["Arn"]

    with ThreadPoolExecutor(max_workers=racers) as ex:
        arns = list(ex.map(attempt, range(racers)))

    assert len(arns) == racers
    assert len(set(arns)) == 1, f"expected every racer to see the same queue ARN, got {arns}"

    # the queue genuinely exists exactly once, not duplicated -- independent read at the
    # destination, both by direct lookup and by an independent list-based side channel
    got = mc.get_queue(Name=name)["Queue"]
    assert got["Arn"] == arns[0]
    assert got["Name"] == name

    listed = [q for page in mc.get_paginator("list_queues").paginate() for q in page["Queues"]]
    matching = [q for q in listed if q["Name"] == name]
    assert len(matching) == 1, f"expected exactly one listed queue named {name}, found {matching}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
