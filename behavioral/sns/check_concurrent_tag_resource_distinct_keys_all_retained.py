"""concurrent-tag-resource-distinct-keys-all-retained."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-distinct-keys-all-retained"
GROUP = 'tagging'
SERVICES = ['sns']

_WRITERS = 12


def _tag_with_retry(sns, arn, key, value, attempts=8):
    """TagResource, retrying only on the documented ConcurrentAccess conflict."""
    for _ in range(attempts):
        try:
            sns.tag_resource(ResourceArn=arn, Tags=[{"Key": key, "Value": value}])
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConcurrentAccess":
                raise
            time.sleep(0.5)
    raise AssertionError(f"TagResource for {key!r} kept conflicting after {attempts} attempts")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Twelve concurrent TagResource calls on one topic, each adding a distinct key, leave all
    twelve keys plus the creation tag: no writer's tag is lost to a read-modify-write race.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-cctag-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    wanted = {f"k{i:02d}": f"v{i:02d}" for i in range(_WRITERS)}
    with ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        futures = [pool.submit(_tag_with_retry, sns, arn, k, v) for k, v in wanted.items()]
        for f in futures:
            f.result()

    stored = {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    missing = sorted(set(wanted) - set(stored))
    assert not missing, f"{len(missing)} concurrently written tag(s) were lost: {missing!r}"
    assert stored == {"sim2real": CHECK, **wanted}, (
        f"the tag set after the concurrent writes must be exactly the 13 keys, got {stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
