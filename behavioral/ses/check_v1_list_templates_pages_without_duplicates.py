"""v1-list-templates-pages-without-duplicates."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "v1-list-templates-pages-without-duplicates"
GROUP = "templates-v1"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTemplates with MaxItems=1 lists every created template exactly once across the full
    NextToken walk, with no duplicates and no page larger than one item.
    """
    ses = ctx.client("ses")

    names = [ctx.unique_name("sim2real-v1tpl-") for _ in range(3)]
    for name in names:
        ses.create_template(Template={"TemplateName": name, "SubjectPart": "s", "TextPart": "t"})
        ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    # ListTemplates can briefly lag CreateTemplate; re-walk until every created template appears.
    listed: list[str] = []
    deadline = time.monotonic() + 30
    while True:
        listed = _walk_all_pages(ses)
        ours_listed = [n for n in listed if n in names]
        if sorted(ours_listed) == sorted(names) or time.monotonic() >= deadline:
            break
        time.sleep(1)

    assert len(listed) == len(set(listed)), f"ListTemplates paging produced a duplicate: {listed!r}"
    assert sorted(ours_listed) == sorted(names), (
        f"expected every created template to appear exactly once across the walk; "
        f"created={names!r}, found={ours_listed!r}"
    )


def _walk_all_pages(ses) -> list[str]:
    listed: list[str] = []
    token = None
    pages = 0
    while True:
        pages += 1
        assert pages <= 1000, "ListTemplates paging did not terminate within a sane bound"
        kwargs = {"MaxItems": 1}
        if token:
            kwargs["NextToken"] = token
        page = ses.list_templates(**kwargs)
        page_names = [m["Name"] for m in page.get("TemplatesMetadata", [])]
        assert len(page_names) <= 1, f"expected at most 1 item per page, got {page_names!r}"
        listed.extend(page_names)
        token = page.get("NextToken")
        if not token:
            return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
