"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["translate"]


def _client_error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected TagResource to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag set that would push the resource over the 50 user-defined tag limit
    (while staying within the 200-item array-size bound so the request passes shape validation and
    reaches the business-rule check); existing tags are untouched by the rejected call."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    create_resp = translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nHello,Hola\n", "Format": "CSV"},
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))
    arn = create_resp["TerminologyProperties"]["Arn"]

    # 60 tags exceeds the 50-tag business limit but stays under the 200-item array-size bound,
    # so this exercises TooManyTagsException rather than a request-shape ValidationException.
    too_many_tags = [{"Key": f"k{i}", "Value": "v"} for i in range(60)]
    code, message = _client_error(lambda: translate.tag_resource(ResourceArn=arn, Tags=too_many_tags))
    assert code == "TooManyTagsException", (
        f"a 60-tag TagResource call was rejected with {code!r}, expected 'TooManyTagsException'"
    )
    assert message == "Allowable tag limit for resource exceeded", (
        f"expected the tag-limit message, got {message!r}"
    )

    # effect absent: no tags were applied by the rejected call
    tags_after_reject = translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after_reject == [], (
        f"the rejected 60-tag call still applied tags: {tags_after_reject!r}, expected none"
    )

    # positive control: a valid, small tag set is applied successfully
    translate.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "test"}])
    tags_after_valid = translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert {"Key": "env", "Value": "test"} in tags_after_valid, (
        f"a valid single-tag TagResource call did not apply, got tags {tags_after_valid!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
