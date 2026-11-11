"""concurrent-tag-resource-additions-merge."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-additions-merge"
GROUP = "concurrency"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public is only usable in us-east-1 (real AWS); ctx.client()'s ``region`` override
    pins this client to that region on both real AWS and the emulator, so no per-target fork
    is needed here."""
    from botocore.config import Config

    return ctx.client(
        "ecr-public",
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls adding *different* tag keys to the same repository ARN
    result in the union of all tags being present afterward -- no lost update from one
    racer clobbering the other's addition."""
    ecrp = _ecrpub_client(ctx)

    repo_name = ctx.unique_name("sim2real-tagmerge-")
    created = ecrp.create_repository(repositoryName=repo_name)
    repo_arn = created["repository"]["repositoryArn"]
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    tag_sets = [
        [{"Key": "sim2real-team-a", "Value": "payments"}],
        [{"Key": "sim2real-team-b", "Value": "checkout"}],
    ]

    def _tag(tags):
        return ecrp.tag_resource(resourceArn=repo_arn, tags=tags)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_tag, tags) for tags in tag_sets]
        for f in futures:
            f.result(timeout=30)

    final_tags = {
        t["Key"]: t["Value"]
        for t in ecrp.list_tags_for_resource(resourceArn=repo_arn)["tags"]
    }
    assert final_tags.get("sim2real-team-a") == "payments", (
        f"lost update: writer A's tag missing from final tag set {final_tags!r}"
    )
    assert final_tags.get("sim2real-team-b") == "checkout", (
        f"lost update: writer B's tag missing from final tag set {final_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
