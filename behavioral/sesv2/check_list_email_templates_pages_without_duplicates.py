"""list-email-templates-pages-without-duplicates."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-email-templates-pages-without-duplicates"
GROUP = "templates-v2"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEmailTemplates with PageSize=1 lists every template this check created exactly once
    across the NextToken walk, with no duplicates and no page larger than the requested size.
    """
    sesv2 = ctx.client("sesv2")

    names = [ctx.unique_name("sim2real-v2tpl-") for _ in range(3)]
    for name in names:
        sesv2.create_email_template(
            TemplateName=name, TemplateContent={"Subject": "s", "Text": "t"}, Tags=[{"Key": "sim2real", "Value": CHECK}]
        )
        ctx.on_cleanup(lambda _n=name: sesv2.delete_email_template(TemplateName=_n))

    # ListEmailTemplates can briefly lag CreateEmailTemplate, so the full walk is polled.
    # botocore has no paginator for this operation; pages are chained by NextToken by hand.
    listed: list[str] = []
    deadline = time.monotonic() + 30
    while True:
        listed = _walk_all_pages(sesv2)
        ours_listed = [n for n in listed if n in names]
        if sorted(ours_listed) == sorted(names) or time.monotonic() >= deadline:
            break
        time.sleep(1)

    assert len(listed) == len(set(listed)), (
        f"ListEmailTemplates paging produced a duplicate: {listed!r}"
    )
    assert sorted(ours_listed) == sorted(names), (
        f"expected every created template to appear exactly once across the walk; "
        f"created={names!r}, found={ours_listed!r}"
    )


def _walk_all_pages(sesv2) -> list[str]:
    listed: list[str] = []
    token = None
    pages = 0
    while True:
        pages += 1
        assert pages <= 1000, "ListEmailTemplates paging did not terminate within a sane bound"
        kwargs = {"PageSize": 1}
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_email_templates(**kwargs)
        page_names = [m["TemplateName"] for m in page.get("TemplatesMetadata", [])]
        assert len(page_names) <= 1, f"expected at most 1 item per page, got {page_names!r}"
        listed.extend(page_names)
        token = page.get("NextToken")
        if not token:
            return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
