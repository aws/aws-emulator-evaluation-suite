"""tag-resource-add-and-remove-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-add-and-remove-roundtrip"
GROUP = "tagging"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource, and UntagResource removes exactly
    the specified key while leaving the rest of the tag set intact."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-tag-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
            "tags": {"stage": "initial"},
        },
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id))

    arn = _component_arn(ctx, app_id, _ENV, comp_id)

    tags = uib.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"stage": "initial"}, f"expected tags at creation to be {{'stage': 'initial'}}, got {tags}"

    uib.tag_resource(resourceArn=arn, tags={"team": "uib"})
    tags = uib.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"stage": "initial", "team": "uib"}, (
        f"expected TagResource to add 'team' while keeping 'stage', got {tags}"
    )

    uib.untag_resource(resourceArn=arn, tagKeys=["stage"])
    tags = uib.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"team": "uib"}, f"expected UntagResource to remove only 'stage', got {tags}"


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name)
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _component_arn(ctx, app_id, env, comp_id):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return (
        f"arn:aws:amplifyuibuilder:{ctx.region}:{account}:"
        f"app/{app_id}/environment/{env}/components/{comp_id}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
