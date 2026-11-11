"""list-tags-on-untagged-parameters-returns-empty-tag-list."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-on-untagged-parameters-returns-empty-tag-list"
GROUP = "tagging"
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


def _tags(ssm, resource_id: str) -> list:
    """The parameter's TagList sorted by key; tag order is not part of the contract."""
    tag_list = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=resource_id)["TagList"]
    return sorted(tag_list, key=lambda t: t["Key"])


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a parameter put without tags answers an empty TagList, not an error.

    Holds for a hierarchical String, a SecureString, a StringList and an Advanced-tier parameter.
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-notags-")
    params = [
        (f"{base}/a/b/c", {"Type": "String", "Value": "plain"}),
        (f"{base}/secure", {"Type": "SecureString", "Value": "secret"}),
        (f"{base}/list", {"Type": "StringList", "Value": "x,y"}),
        (f"{base}/advanced", {"Type": "String", "Value": "adv", "Tier": "Advanced"}),
    ]
    for name, kwargs in params:
        ssm.put_parameter(Name=name, **kwargs)
        ctx.on_cleanup(_teardown(lambda name=name: ssm.delete_parameter(Name=name),
                                 "ParameterNotFound"))

    for name, kwargs in params:
        resp = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)
        assert "TagList" in resp, f"{kwargs['Type']} {name!r}: response has no TagList: {resp!r}"
        assert resp["TagList"] == [], f"untagged {name!r} lists {resp['TagList']!r}"

    pages = ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Values": [n for n, _ in params]}]
    )
    tiers = {p["Name"]: (p["Type"], p["Tier"]) for page in pages for p in page["Parameters"]}
    want = {n: (k["Type"], k.get("Tier", "Standard")) for n, k in params}
    assert tiers == want, f"parameters described as {tiers!r}, expected {want!r}"

    # Tagging one parameter leaves the others' empty TagList untouched.
    tagged = params[0][0]
    ssm.add_tags_to_resource(ResourceType="Parameter", ResourceId=tagged,
                             Tags=[{"Key": "owner", "Value": "alpha"}])
    assert _tags(ssm, tagged) == [{"Key": "owner", "Value": "alpha"}], (
        f"tagged {tagged!r} lists {_tags(ssm, tagged)!r}"
    )
    for name, _ in params[1:]:
        assert _tags(ssm, name) == [], f"{name!r} picked up tags: {_tags(ssm, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

