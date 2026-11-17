"""workgroup-get-and-list-agree-while-live."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-get-and-list-agree-while-live"
GROUP = 'workgroup'
SERVICES = ['athena']


def _list_all(athena, method_name, result_key, **kwargs):
    method = getattr(athena, method_name)
    items = []
    token = None
    while True:
        call = dict(kwargs)
        if token:
            call["NextToken"] = token
        resp = method(**call)
        items.extend(resp.get(result_key, []))
        token = resp.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """While a workgroup is live, GetWorkGroup and ListWorkGroups report the same
    State, Description and CreationTime for it.
    """
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    description = "workgroup get and list agreement check"

    athena.create_work_group(
        Name=name,
        Description=description,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    got = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["State"] == "ENABLED", f"expected State='ENABLED', got {got['State']!r}"
    assert got["Description"] == description, (
        f"expected Description={description!r}, got {got['Description']!r}"
    )

    summary = None
    for wg in _list_all(athena, "list_work_groups", "WorkGroups"):
        if wg["Name"] == name:
            summary = wg
            break
    assert summary is not None, f"workgroup {name!r} missing from ListWorkGroups while live"

    assert summary["State"] == got["State"], (
        f"ListWorkGroups State {summary['State']!r} disagrees with GetWorkGroup State {got['State']!r}"
    )
    assert summary["Description"] == got["Description"], (
        f"ListWorkGroups Description {summary['Description']!r} disagrees with "
        f"GetWorkGroup Description {got['Description']!r}"
    )
    assert summary["CreationTime"] == got["CreationTime"], (
        f"ListWorkGroups CreationTime {summary['CreationTime']!r} disagrees with "
        f"GetWorkGroup CreationTime {got['CreationTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
