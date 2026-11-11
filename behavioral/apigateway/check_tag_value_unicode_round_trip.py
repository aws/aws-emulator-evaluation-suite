"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters in tag keys/values on a REST API resource survive a
    TagResource -> GetTags round-trip unchanged."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"
    tags = {
        "ünïcödé-këy": "日本語-tëst_value",
        "plain": "válue-with-áccents",
    }

    apigw.tag_resource(resourceArn=resource_arn, tags=tags)

    got = apigw.get_tags(resourceArn=resource_arn)
    for key, value in tags.items():
        actual = got["tags"][key]
        assert actual == value, f"tag {key!r} did not round-trip unchanged: sent={value!r} got={actual!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
