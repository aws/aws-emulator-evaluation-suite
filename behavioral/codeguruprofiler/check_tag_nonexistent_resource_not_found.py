"""tag-nonexistent-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource against a real profiling group succeeds and the tag is visible
    via an independent read (positive control); the identical call against a
    well-formed but non-existent profiling group ARN returns NotFoundException."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    real_name = ctx.unique_name("sim2real-cgp-tagreal-")
    real_arn = cgp.create_profiling_group(
        profilingGroupName=real_name, computePlatform="Default"
    )["profilingGroup"]["arn"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    cgp.tag_resource(resourceArn=real_arn, tags={"a": "b"})
    read_back = cgp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert read_back == {"a": "b"}, read_back

    missing_name = ctx.unique_name("sim2real-cgp-missing-")
    missing_arn = f"arn:aws:codeguru-profiler:{ctx.region}:{account_id}:profilingGroup/{missing_name}"

    err = _error(lambda: cgp.tag_resource(resourceArn=missing_arn, tags={"a": "b"}))
    assert err["Code"] == "NotFoundException", err
    assert err["Message"] == "Resource was not found", err["Message"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
