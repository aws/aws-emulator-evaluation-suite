"""concurrent-tag-resource-merge-no-lost-writes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-merge-no-lost-writes"
GROUP = "concurrency"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent TagResource callers, each adding a distinct tag key to the
    same profile, all land: the final tag set contains every key with no lost
    writes under contention."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
    )["profile"]
    profile_id = profile["profileId"]
    profile_arn = profile["profileArn"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    worker_count = 10
    keys = [f"racer-{i}" for i in range(worker_count)]

    def _tag_one(key: str) -> None:
        ra.tag_resource(resourceArn=profile_arn, tags=[{"key": key, "value": "v"}])

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(_tag_one, key) for key in keys]
        for future in as_completed(futures):
            future.result()

    final_tags = {t["key"] for t in ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]}
    for key in keys:
        assert key in final_tags, f"lost write: {key!r} missing from final tag set {final_tags!r}"
    assert len(final_tags) == worker_count, f"expected {worker_count} tags, found {len(final_tags)}: {final_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
