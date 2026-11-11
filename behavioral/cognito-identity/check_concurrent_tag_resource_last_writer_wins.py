"""concurrent-tag-resource-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing TagResource calls with conflicting values on the same key resolve deterministically."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = _pool_arn(ctx, pool_id)

    candidate_values = [f"racer-value-{i}" for i in range(6)]

    def _tag(value: str) -> None:
        ci.tag_resource(ResourceArn=arn, Tags={"race-key": value})

    with ThreadPoolExecutor(max_workers=len(candidate_values)) as pool:
        futures = [pool.submit(_tag, value) for value in candidate_values]
        for f in futures:
            f.result(timeout=30)  # propagate any exception; all racers must succeed

    final_tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    final_value = final_tags.get("race-key")
    assert final_value in candidate_values, (
        f"final tag value {final_value!r} was not one of the racing writes {candidate_values} "
        "(corrupted/merged state instead of a clean last-writer-wins resolution)"
    )

    # Re-reading must be stable (no lingering inconsistency across repeated reads).
    for _ in range(3):
        again = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
        assert again.get("race-key") == final_value, "tag value is not stable after the race settled"


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
