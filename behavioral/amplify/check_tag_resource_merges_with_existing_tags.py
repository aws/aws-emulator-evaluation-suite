"""tag-resource-merges-with-existing-tags."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-merges-with-existing-tags"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges new tags into the existing tag set instead of replacing it."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"k1": "v1"})["app"]
    app_id = app["appId"]
    app_arn = app["appArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))

    amplify.tag_resource(resourceArn=app_arn, tags={"k2": "v2"})

    tags = amplify.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert tags == {"k1": "v1", "k2": "v2"}, tags


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
