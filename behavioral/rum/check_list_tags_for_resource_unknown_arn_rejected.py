"""list-tags-for-resource-unknown-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-unknown-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource distinguishes two rejection classes: a syntactically valid but
    non-existent app monitor ARN -> NotFoundException, vs a malformed ARN ->
    BadRequestException. A real, tagged app monitor is used as the positive control."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, DomainList=["example.com"])
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)
    rum.tag_resource(ResourceArn=arn, Tags={"sim2real-control": "present"})

    # Positive control: the real, tagged resource is readable.
    control_tags = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert control_tags.get("sim2real-control") == "present", (
        f"expected control tag 'present' on {arn}, got {control_tags!r}"
    )

    # (a) syntactically valid ARN, but no such app monitor exists.
    # Empirically, the RUM service surfaces this as the generic "NotFoundException"
    # (not the tagging-shape "ResourceNotFoundException" some other services use).
    missing_arn = _app_monitor_arn(ctx, ctx.unique_name("sim2real-rum-missing-"))
    code_missing, message_missing = _client_error(lambda: rum.list_tags_for_resource(ResourceArn=missing_arn))
    assert code_missing == "NotFoundException", (
        f"expected NotFoundException for a well-formed but non-existent ARN, got {code_missing!r}"
    )
    assert message_missing == "Resource was not found", message_missing

    # (b) malformed ARN (does not match the ARN pattern at all). RUM surfaces this as a
    # generic framework-level BadRequestException (URI-pattern rejection) rather than the
    # modeled ValidationException.
    code_malformed, message_malformed = _client_error(lambda: rum.list_tags_for_resource(ResourceArn="not-an-arn"))
    assert code_malformed == "BadRequestException", (
        f"expected BadRequestException for a malformed ARN, got {code_malformed!r}"
    )
    assert message_malformed == "Invalid input resource arn: bad syntax", message_malformed

    # Control still holds after the negative calls (isolation from the rejected requests).
    control_tags_after = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert control_tags_after.get("sim2real-control") == "present", (
        f"expected control tag 'present' on {arn} after the rejected calls, got {control_tags_after!r}"
    )


def _app_monitor_arn(ctx, name: str) -> str:
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    return f"arn:{partition}:rum:{ctx.region}:{account}:appmonitor/{name}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
