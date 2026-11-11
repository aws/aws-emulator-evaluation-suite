"""list-groups-filter-by-resource-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-groups-filter-by-resource-type"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups Filters=[resource-type=...] returns only the group whose query targets that type,
    and a deleted group is genuinely gone from both that filtered view and a direct read."""
    rg = ctx.client("resource-groups")

    name_a = ctx.unique_name("sim2real-rg-groupA-")
    name_b = ctx.unique_name("sim2real-rg-groupB-")

    def _nomatch_query(resource_type, marker):
        return {
            "Type": "TAG_FILTERS_1_0",
            "Query": (
                '{"ResourceTypeFilters":["' + resource_type + '"],'
                '"TagFilters":[{"Key":"sim2real-restype-nomatch","Values":["' + marker + '"]}]}'
            ),
        }

    rg.create_group(
        Name=name_a,
        ResourceQuery=_nomatch_query("AWS::SQS::Queue", name_a),
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: rg.delete_group(Group=name_a)))
    rg.create_group(
        Name=name_b,
        ResourceQuery=_nomatch_query("AWS::S3::Bucket", name_b),
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: rg.delete_group(Group=name_b)))

    resp = rg.list_groups(Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}], MaxResults=50)
    names = {g["GroupName"] for g in resp["GroupIdentifiers"]}
    assert name_a in names, f"expected {name_a} (SQS-typed query) in resource-type=AWS::SQS::Queue results, got {names}"
    assert name_b not in names, f"expected {name_b} (S3-typed query) excluded from AWS::SQS::Queue filter, got {names}"

    rg.delete_group(Group=name_a)

    code, message = _client_error(lambda: rg.get_group(GroupName=name_a), expect="NotFoundException")
    assert code == "NotFoundException", f"expected NotFoundException reading a deleted group, got {code!r}"
    assert message == "The specified group does not exist", f"GetGroup on a deleted group returned message {message!r}"

    resp_after = rg.list_groups(Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}], MaxResults=50)
    names_after = {g["GroupName"] for g in resp_after["GroupIdentifiers"]}
    assert name_a not in names_after, f"deleted group {name_a} must not reappear in the resource-type filtered list"


def _client_error(fn, *, expect):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {expect} but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
