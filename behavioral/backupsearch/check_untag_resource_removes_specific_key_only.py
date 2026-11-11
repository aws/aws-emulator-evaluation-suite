"""untag-resource-removes-specific-key-only."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-removes-specific-key-only"
GROUP = "tagging"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with one of several tag keys removes only that key, leaving the others
    intact."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    job_arn = started["SearchJobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bs.tag_resource(ResourceArn=job_arn, Tags={"sim2real-a": "1", "sim2real-b": "2"})
    bs.untag_resource(ResourceArn=job_arn, TagKeys=["sim2real-a"])

    after = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert after["Tags"] == {"sim2real-b": "2"}, (
        f"expected only sim2real-b to remain after untagging sim2real-a, got {after['Tags']!r}"
    )


def _best_effort_stop(bs, job_id: str) -> None:
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
