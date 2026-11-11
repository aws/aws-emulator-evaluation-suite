"""list-dictionaries-pagination-maxresults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-dictionaries-pagination-maxresults"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDictionaries with maxResults=1 pages through results without duplicating or dropping created dictionaries."""
    ei = ctx.client("elementalinference")
    created_ids = []
    for _ in range(3):
        name = ctx.unique_name("sim2real-ei-dict-")
        dict_id = ei.create_dictionary(
            name=name, language="eng", entries='[{"content": "par"}, {"content": "bogey"}]',
            tags={"Environment": "sim2real-behav"},
        )["id"]
        created_ids.append(dict_id)
        ctx.on_cleanup(lambda d=dict_id: ei.delete_dictionary(id=d))

    seen_ids = []
    token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = ei.list_dictionaries(**kwargs)
        pages += 1
        assert len(page["dictionaries"]) <= 1, f"maxResults=1 but page had {len(page['dictionaries'])} items"
        seen_ids.extend(d["id"] for d in page["dictionaries"])
        token = page.get("nextToken")
        if not token or pages > 200:
            break

    for dict_id in created_ids:
        assert seen_ids.count(dict_id) == 1, f"dictionary {dict_id} appeared {seen_ids.count(dict_id)} times"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
