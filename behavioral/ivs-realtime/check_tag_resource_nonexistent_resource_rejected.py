"""tag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a never-existing ARN fails NotFoundException "Resource was not found", tagging a real stage
    succeeds, and after the stage is deleted the same TagResource fails the same way."""
    ivsrt = ctx.client("ivs-realtime")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:ivs:{ctx.region}:{account}:encoder-configuration/{uuid.uuid4().hex[:12]}"
    )

    code, message = _error(lambda: ivsrt.tag_resource(resourceArn=bogus_arn, tags={"k": "v"}))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Resource was not found", message

    created = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-ivsrt-enc-")
    )["encoderConfiguration"]
    arn = created["arn"]
    deleted = False
    ctx.on_cleanup(lambda: None if deleted else ivsrt.delete_encoder_configuration(arn=arn))

    ivsrt.tag_resource(resourceArn=arn, tags={"k": "v"})
    tags_after_tag = ivsrt.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_tag == {"k": "v"}, f"expected {{'k': 'v'}}, got {tags_after_tag}"

    ivsrt.delete_encoder_configuration(arn=arn)
    deleted = True
    not_found_code, not_found_message = _error(lambda: ivsrt.get_encoder_configuration(arn=arn))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted encoder configuration, got {not_found_code}"
    )
    assert not_found_message == f"Resource: {arn} not found", not_found_message
    dead_arn_code, dead_arn_message = _error(lambda: ivsrt.tag_resource(resourceArn=arn, tags={"k": "v"}))
    assert dead_arn_code == "NotFoundException", (
        f"expected NotFoundException tagging a deleted encoder configuration, got {dead_arn_code}"
    )
    assert dead_arn_message == "Resource was not found", dead_arn_message


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
