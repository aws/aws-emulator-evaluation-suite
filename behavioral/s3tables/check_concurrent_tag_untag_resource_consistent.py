"""concurrent-tag-untag-resource-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-tag-untag-resource-consistent"
GROUP = "concurrency"
SERVICES = ["s3tables"]

_RACER_COUNT = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource (new keys) and UntagResource (baseline keys) on one bucket converge to
    exactly the new keys: no lost update from a non-atomic read-modify-write, no partial entries."""
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-tag-race-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, bucket_arn))

    baseline = {f"base-{i}": f"basev-{i}" for i in range(_RACER_COUNT)}
    s3tables.tag_resource(resourceArn=bucket_arn, tags=baseline)

    def _add(i: int):
        s3tables.tag_resource(resourceArn=bucket_arn, tags={f"racer-{i}": f"racerv-{i}"})
        return True

    def _remove(i: int):
        s3tables.untag_resource(resourceArn=bucket_arn, tagKeys=[f"base-{i}"])
        return True

    with ThreadPoolExecutor(max_workers=2 * _RACER_COUNT) as pool:
        futures = [pool.submit(_add, i) for i in range(_RACER_COUNT)]
        futures += [pool.submit(_remove, i) for i in range(_RACER_COUNT)]
        results = [f.result() for f in as_completed(futures)]

    assert all(results), "not every concurrent tag/untag call succeeded"

    final_tags = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]

    for i in range(_RACER_COUNT):
        assert final_tags.get(f"racer-{i}") == f"racerv-{i}", (
            f"racer-{i} tag missing or wrong value: {final_tags}"
        )
        assert f"base-{i}" not in final_tags, f"base-{i} tag was not removed: {final_tags}"

    assert len(final_tags) == _RACER_COUNT, f"unexpected extra/missing tags: {final_tags}"


def _delete_bucket_quiet(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
