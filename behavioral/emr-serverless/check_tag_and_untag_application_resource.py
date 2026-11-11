"""tag-and-untag-application-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-and-untag-application-resource"
GROUP = "tags"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied at creation, added via TagResource, and removed via UntagResource are all
    reflected by ListTagsForResource."""
    emrs = ctx.client("emr-serverless")
    resp = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        tags={"env": "test"},
    )
    app_id = resp["applicationId"]
    app_arn = resp["arn"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    tags_after_create = emrs.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert tags_after_create == {"env": "test"}, (
        f"expected creation-time tags {{'env': 'test'}}, got {tags_after_create}"
    )

    emrs.tag_resource(resourceArn=app_arn, tags={"team": "data"})
    tags_after_add = emrs.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert tags_after_add == {"env": "test", "team": "data"}, (
        f"expected {{'env': 'test', 'team': 'data'}} after TagResource, got {tags_after_add}"
    )

    emrs.untag_resource(resourceArn=app_arn, tagKeys=["env"])
    tags_after_remove = emrs.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert tags_after_remove == {"team": "data"}, (
        f"expected {{'team': 'data'}} after UntagResource(['env']), got {tags_after_remove}"
    )


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
