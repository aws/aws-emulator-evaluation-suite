"""tags-unicode-value-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-unicode-value-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode-letter tag values (accents, CJK, Cyrillic, Greek) round-trip through TagResource and
    GetTags, while an emoji value is rejected with BadRequestException and not applied."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"
    tags = {
        "team": "日本語チーム",
        "owner": "café-naïve-Ω",
        "region": "北京-Москва",
    }
    apigw.tag_resource(resourceArn=resource_arn, tags=tags)
    ctx.on_cleanup(lambda: apigw.untag_resource(resourceArn=resource_arn, tagKeys=list(tags.keys())))

    got = apigw.get_tags(resourceArn=resource_arn)["tags"]
    for key, value in tags.items():
        assert got.get(key) == value, f"tag {key!r}: expected {value!r}, got {got.get(key)!r}"

    # Emoji are symbol-category characters, outside the allowed tag-value character class.
    err = _client_error(
        lambda: apigw.tag_resource(resourceArn=resource_arn, tags={"emoji": "🎉🔥"})
    )
    code = err.get("Code")
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert err.get("Message") == (
        "Invalid tag key/value. Valid characters are letters, numbers, spaces, and the following: "
        "_ . : / = + - @. Tag key can be up to 128 characters. Tag value can be up to 256 characters."
    ), f"expected the exact tag character-class refusal message, got {err.get('Message')!r}"

    after_reject = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert "emoji" not in after_reject, (
        f"emoji tag was rejected with {code} but still present: {after_reject.get('emoji')!r}"
    )


def _client_error(fn):
    """The botocore Error dict of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
