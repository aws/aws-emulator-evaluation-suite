"""workgroup-list-contains-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-list-contains-created"
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
    """ListWorkGroups surfaces a newly created WorkGroup with the right state."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")

    before_names = {wg["Name"] for wg in _list_all(athena, "list_work_groups", "WorkGroups")}
    assert name not in before_names, f"workgroup name {name} unexpectedly already listed before creation"

    athena.create_work_group(Name=name, Tags=[{"Key": "sim2real-check", "Value": "workgroup-list-contains-created"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    found = None
    for wg in _list_all(athena, "list_work_groups", "WorkGroups"):
        if wg["Name"] == name:
            found = wg
            break

    assert found is not None, "created workgroup not found in ListWorkGroups"
    assert found["State"] == "ENABLED", f"expected ENABLED, got {found['State']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
