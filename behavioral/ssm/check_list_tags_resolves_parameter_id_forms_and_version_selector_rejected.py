"""list-tags-resolves-parameter-id-forms-and-version-selector-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-resolves-parameter-id-forms-and-version-selector-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _tags(ssm, resource_id: str) -> list:
    """The parameter's TagList sorted by key; tag order is not part of the contract."""
    tag_list = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=resource_id)["TagList"]
    return sorted(tag_list, key=lambda t: t["Key"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Parameter tags list by name, by name without its leading slash and by ARN; a version
    selector or the Document resource type for that name answers InvalidResourceId.
    """
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-tagids-") + "/svc/key"
    created = [{"Key": "owner", "Value": "alpha"}, {"Key": "tier", "Value": "gold"}]
    ssm.put_parameter(Name=name, Value="v1", Type="String", Tags=created)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))
    arn = ssm.get_parameter(Name=name)["Parameter"]["ARN"]
    assert arn == f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{name}", (
        f"GetParameter ARN has an unexpected form: {arn!r}"
    )

    for form, resource_id in (("name", name), ("name without leading slash", name[1:]),
                              ("ARN", arn)):
        got = _tags(ssm, resource_id)
        assert got == created, f"ListTagsForResource by {form} lists {got!r}, expected {created!r}"

    got = _error(lambda: ssm.list_tags_for_resource(ResourceType="Parameter",
                                                    ResourceId=f"{name}:1"))
    assert got == ("InvalidResourceId", ""), f"a version-selected name gave {got!r}"
    got = _error(lambda: ssm.list_tags_for_resource(ResourceType="Document", ResourceId=name))
    assert got == ("InvalidResourceId", ""), f"ResourceType Document for a parameter gave {got!r}"

    got = _error(lambda: ssm.add_tags_to_resource(ResourceType="Parameter",
                                                  ResourceId=f"{name}:1",
                                                  Tags=[{"Key": "owner", "Value": "beta"}]))
    assert got == ("InvalidResourceId", ""), f"AddTagsToResource on a version selector gave {got!r}"
    assert _tags(ssm, name) == created, f"refused calls changed tags to {_tags(ssm, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

