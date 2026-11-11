"""put-parameter-overwrite-with-tags-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-overwrite-with-tags-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutParameter with Overwrite and Tags together is refused, for an existing name and a new one,
    leaving value, version and tags unchanged; the same overwrite without Tags succeeds.
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-owtags-")
    name, fresh = f"{base}/existing", f"{base}/fresh"
    created = [{"Key": "owner", "Value": "alpha"}]
    ssm.put_parameter(Name=name, Value="v1", Type="String", Tags=created)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))
    # A wrongly accepted create would otherwise leak the fresh name.
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=fresh), "ParameterNotFound"))

    refusal = (
        "ValidationException",
        "Invalid request: tags and overwrite can't be used together. To create a parameter with "
        "tags, please remove overwrite flag. To update tags for an existing parameter, please use "
        "AddTagsToResource or RemoveTagsFromResource.",
    )
    got = _error(lambda: ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True,
                                           Tags=[{"Key": "owner", "Value": "beta"}]))
    assert got == refusal, f"Overwrite+Tags on an existing name gave {got!r}"
    param = ssm.get_parameter(Name=name)["Parameter"]
    assert (param["Value"], param["Version"]) == ("v1", 1), (
        f"refused overwrite changed the parameter to {param['Value']!r} v{param['Version']}"
    )
    assert _tags(ssm, name) == created, f"refused overwrite changed tags to {_tags(ssm, name)!r}"

    got = _error(lambda: ssm.put_parameter(Name=fresh, Value="v1", Type="String", Overwrite=True,
                                           Tags=[{"Key": "owner", "Value": "beta"}]))
    assert got == refusal, f"Overwrite+Tags on a new name gave {got!r}"
    got = _error(lambda: ssm.get_parameter(Name=fresh))
    assert got == ("ParameterNotFound", ""), f"the refused create left {fresh!r}: {got!r}"

    # Positive control: the same overwrite without Tags lands and keeps the create-time tags.
    version = ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True)["Version"]
    assert version == 2, f"overwrite without Tags answered Version {version!r}"
    value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert value == "v2", f"overwrite without Tags left value {value!r}"
    assert _tags(ssm, name) == created, f"overwrite without Tags left {_tags(ssm, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

