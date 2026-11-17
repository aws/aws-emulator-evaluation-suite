"""concurrent-create-tags-on-the-same-resource-do-not-lose-updates."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-create-tags-on-the-same-resource-do-not-lose-updates"
GROUP = "tagging"
SERVICES = ["ec2"]

_WRITER_COUNT = 5


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateTags calls on one resource, each setting a distinct key, all land; a
    second round racing on one shared key leaves it holding one of the submitted values."""
    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id

    group_name = ctx.unique_name("sim2real-tagconc-")
    sg_id = ec2.create_security_group(
        GroupName=group_name,
        Description="sim2real concurrent tag writers check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": group_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    # --- distinct keys, concurrent writers: every write lands, none is lost ---
    distinct_pairs = {f"sim2real-writer-{i}": f"value-{i}" for i in range(_WRITER_COUNT)}
    with ThreadPoolExecutor(max_workers=_WRITER_COUNT) as pool:
        futures = [
            pool.submit(ec2.create_tags, Resources=[sg_id], Tags=[{"Key": key, "Value": value}])
            for key, value in distinct_pairs.items()
        ]
        for future in as_completed(futures):
            future.result()

    after_distinct = _await_tags(
        ec2, sg_id, lambda got: all(got.get(k) == v for k, v in distinct_pairs.items())
    )
    for key, value in distinct_pairs.items():
        assert after_distinct.get(key) == value, (
            f"expected {key}={value!r} after concurrent distinct-key writers, "
            f"got {after_distinct.get(key)!r}"
        )

    # --- shared key, concurrent writers: the key survives holding one submitted value ---
    shared_key = "sim2real-shared-writer-key"
    shared_values = [f"race-value-{i}" for i in range(_WRITER_COUNT)]
    with ThreadPoolExecutor(max_workers=_WRITER_COUNT) as pool:
        futures = [
            pool.submit(ec2.create_tags, Resources=[sg_id], Tags=[{"Key": shared_key, "Value": value}])
            for value in shared_values
        ]
        for future in as_completed(futures):
            future.result()

    final = _await_tags(
        ec2, sg_id,
        lambda got: got.get(shared_key) in shared_values
        and all(got.get(k) == v for k, v in distinct_pairs.items()),
    )
    assert final.get(shared_key) in shared_values, (
        f"expected {shared_key!r} to hold one of {shared_values!r} after the race, "
        f"got {final.get(shared_key)!r}"
    )
    for key, value in distinct_pairs.items():
        assert final.get(key) == value, (
            f"the shared-key race disturbed the earlier distinct tag {key}: "
            f"expected {value!r}, got {final.get(key)!r}"
        )


def _await_tags(ec2, resource_id: str, done, timeout_s: float = 60.0) -> dict:
    """The resource's tags once ``done(tags)`` holds, else the last read after ``timeout_s``."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = _tags_of(ec2, resource_id)
        if done(got) or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _tags_of(ec2, resource_id: str) -> dict:
    desc = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])
    return {t["Key"]: t["Value"] for t in desc["Tags"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
