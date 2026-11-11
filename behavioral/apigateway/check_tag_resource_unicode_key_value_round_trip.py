"""tag-resource-unicode-key-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-unicode-key-value-round-trip"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with unicode letters (multi-script: Japanese, Cyrillic, Latin
    diacritics) in tag keys and values on a RestApi; GetTags must return them
    byte-identical (no mangled escaping, no normalization/casing changes)."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    # AWS documents the allowed tag character set as letters/numbers/spaces
    # representable in UTF-8 plus ". : + = @ _ / -" (see "Tag restrictions and usage
    # conventions" in the API Gateway developer guide) -- non-Latin *letters* are
    # allowed, but symbols/emoji are not, so this check sticks to multi-script letters.
    tags = {
        "Sim2Real:日本語Key": "値はÜnïcödéです",
        "Sim2Real:Ключ": "Café-Münster-北京市-Москва",
    }

    apigw.tag_resource(resourceArn=resource_arn, tags=tags)
    ctx.on_cleanup(
        lambda: apigw.untag_resource(resourceArn=resource_arn, tagKeys=list(tags.keys()))
    )

    fetched = apigw.get_tags(resourceArn=resource_arn)["tags"]
    for key, value in tags.items():
        assert key in fetched, f"unicode tag key {key!r} missing from GetTags result"
        assert fetched[key] == value, (
            f"unicode tag value mutated: key={key!r} sent={value!r} got={fetched[key]!r}"
        )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
