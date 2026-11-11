"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "tagging"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a never-set key succeeds and leaves existing tags untouched, while the
    same call with an existing key removes it, so the no-op is specific to the unknown key."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    job_arn = started["SearchJobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bs.tag_resource(ResourceArn=job_arn, Tags={"sim2real-real": "tag"})
    baseline = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert baseline["Tags"] == {"sim2real-real": "tag"}, (
        f"expected baseline tag to be set before the no-op call, got {baseline['Tags']!r}"
    )

    # Untagging an absent key is accepted: a ClientError here fails the check.
    bs.untag_resource(ResourceArn=job_arn, TagKeys=["sim2real-does-not-exist"])

    after_noop = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert after_noop["Tags"] == {"sim2real-real": "tag"}, (
        f"expected tags unchanged after untagging an absent key, got {after_noop['Tags']!r}"
    )

    # Positive control: the identical operation given a key that DOES exist actually removes
    # it, so the no-op result above is a demonstrated no-op rather than an UntagResource that
    # never does anything.
    bs.untag_resource(ResourceArn=job_arn, TagKeys=["sim2real-real"])
    after_control = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert after_control["Tags"] == {}, (
        f"expected untagging an existing key to remove it, got {after_control['Tags']!r}"
    )


def _best_effort_stop(bs, job_id: str) -> None:
    # A job already in a terminal state answers StopSearchJob with ConflictException: nothing to stop.
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        terminal = ("COMPLETED", "FAILED", "STOPPED", "STOPPING")
        if code == "ConflictException" and bs.get_search_job(SearchJobIdentifier=job_id)["Status"] in terminal:
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
