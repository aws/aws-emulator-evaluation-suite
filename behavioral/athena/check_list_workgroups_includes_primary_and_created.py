"""list-workgroups-includes-primary-and-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-workgroups-includes-primary-and-created"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkGroups includes the account's default 'primary' workgroup plus all
    created workgroups, with a deduplicated listing that is stable across pagination."""
    athena = ctx.client("athena")

    created_names: list[str] = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-wg-{i}-")
        athena.create_work_group(
            Name=name,
            Tags=[{"Key": "sim2real", "Value": "list-workgroups-includes-primary-and-created"}],
        )
        created_names.append(name)
        ctx.on_cleanup(lambda name=name: athena.delete_work_group(WorkGroup=name))

    first_pass = _list_all_workgroups(athena)
    second_pass = _list_all_workgroups(athena)

    assert "primary" in first_pass, "default 'primary' workgroup missing from ListWorkGroups"
    for name in created_names:
        count = first_pass.count(name)
        assert count == 1, f"expected workgroup {name} exactly once, saw {count}"

    assert len(first_pass) == len(set(first_pass)), "ListWorkGroups returned a duplicate Name across pages"

    # Compared only over this check's own subjects: the full unscoped listing shares the
    # account with concurrently-running checks, so an unrelated workgroup created or deleted
    # by another agent between the two passes would otherwise read as a pagination defect here.
    relevant = {"primary", *created_names}
    first_relevant = [n for n in first_pass if n in relevant]
    second_relevant = [n for n in second_pass if n in relevant]
    assert first_relevant == second_relevant, (
        f"ListWorkGroups ordering for primary+created workgroups changed across repeated calls: "
        f"{first_relevant!r} != {second_relevant!r}"
    )


def _list_all_workgroups(athena) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_work_groups(**kwargs)
        names.extend(w["Name"] for w in resp.get("WorkGroups", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
