"""list-tags-for-resource-malformed-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-rejected"
GROUP = "validation"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on "this-is-not-an-arn-at-all" fails with ValidationException and its exact ARN-format
    message, while a well-formed nonexistent policy ARN fails with ResourceNotFoundException
    "The referenced item does not exist."."""
    fms = ctx.client("fms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    malformed_code, malformed_message = _client_error(
        lambda: fms.list_tags_for_resource(ResourceArn="this-is-not-an-arn-at-all")
    )
    assert malformed_code == "ValidationException", f"expected ValidationException, got {malformed_code}"
    assert malformed_message == (
        "Incorrect arn format. error:ARNs must start with 'arn:': this-is-not-an-arn-at-all"
    ), f"unexpected ValidationException message: {malformed_message!r}"

    import uuid

    wellformed_arn = f"arn:aws:fms:{ctx.region}:{account_id}:policy/{uuid.uuid4()}"
    notfound_code, notfound_message = _client_error(lambda: fms.list_tags_for_resource(ResourceArn=wellformed_arn))
    assert notfound_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed missing arn, got {notfound_code}"
    )
    assert notfound_message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {notfound_message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
