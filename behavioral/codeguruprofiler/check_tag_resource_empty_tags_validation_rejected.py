"""tag-resource-empty-tags-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-empty-tags-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an empty tags map is rejected with BadRequestException, the
    existing tag set is left unchanged, and TagResource with a non-empty map (positive
    control) still succeeds right after."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    arn = cgp.create_profiling_group(
        profilingGroupName=name,
        tags={"seed": "1"},
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]["arn"]

    err = _error(lambda: cgp.tag_resource(resourceArn=arn, tags={}))
    assert err["Code"] == "BadRequestException", err
    assert err["Message"] == "Invalid request input, expected non-empty tags map", err["Message"]

    unchanged = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert unchanged == {"seed": "1"}, unchanged

    cgp.tag_resource(resourceArn=arn, tags={"seed2": "2"})
    grown = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert grown == {"seed": "1", "seed2": "2"}, grown


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected TagResource to be rejected but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
