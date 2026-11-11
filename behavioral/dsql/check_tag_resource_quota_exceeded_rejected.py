"""tag-resource-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with more than the documented 200-tag-per-resource limit is rejected (empirically
    BadRequestException, not ServiceQuotaExceededException), no tags from the oversized request are
    persisted, and a request within the limit (positive control) succeeds normally."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    too_many_tags = {f"sim2real-k{i}": f"v{i}" for i in range(201)}
    quota_code, quota_message = _error(lambda: dsql.tag_resource(resourceArn=arn, tags=too_many_tags))
    assert quota_code == "BadRequestException", (
        f"a 201-tag TagResource request (over the documented 200-tag-per-resource limit) "
        f"was expected to fail with BadRequestException, got {quota_code!r}"
    )
    assert quota_message == "Invalid request body", quota_message

    # effect absent: none of the oversized batch's tags were persisted
    tags_after = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    leaked = set(too_many_tags) & set(tags_after)
    assert not leaked, f"rejected TagResource call still persisted tags: {sorted(leaked)!r}"

    # positive control: a within-limit tag request succeeds
    dsql.tag_resource(resourceArn=arn, tags={"sim2real-quota-control": "ok"})
    tags_ok = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_ok.get("sim2real-quota-control") == "ok", (
        f"a within-limit TagResource call after the rejection should have succeeded, "
        f"got tags={tags_ok!r}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
