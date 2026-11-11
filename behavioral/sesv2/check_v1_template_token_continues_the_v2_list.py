"""v1-template-token-continues-the-v2-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "v1-template-token-continues-the-v2-list"
GROUP = "templates-v2"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A NextToken minted by the v1 ListTemplates call is accepted by ListEmailTemplates (v2) and
    continues the SAME list: the v2 walk repeats nothing and covers every created template.
    """
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")

    names = [ctx.unique_name("sim2real-v1v2tpl-") for _ in range(2)]
    for name in names:
        ses.create_template(Template={"TemplateName": name, "SubjectPart": "s", "TextPart": "t"})
        ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    first = ses.list_templates(MaxItems=1)
    token = first.get("NextToken")
    assert token, f"expected ListTemplates(MaxItems=1) to mint a NextToken, got {first!r}"
    first_name = first["TemplatesMetadata"][0]["Name"]

    # Walk the v2 list from v1's token to its end: together with v1's first page it must be
    # the whole list -- every template this check created, each exactly once.
    rest_names: list[str] = []
    next_token = token
    for _ in range(1000):
        rest = sesv2.list_email_templates(NextToken=next_token)
        rest_names.extend(m["TemplateName"] for m in rest["TemplatesMetadata"])
        next_token = rest.get("NextToken")
        if not next_token:
            break
    else:
        raise AssertionError("ListEmailTemplates paging from the v1 token did not terminate")
    assert first_name not in rest_names, (
        f"v2's continuation page must not repeat v1's first-page template {first_name!r}, "
        f"got {rest_names!r}"
    )
    walked = [first_name] + rest_names
    assert len(walked) == len(set(walked)), f"the v1+v2 walk repeated a template: {walked!r}"
    missing = [n for n in names if n not in walked]
    assert missing == [], (
        f"the v1 first page plus the v2 continuation must cover every template this check "
        f"created; missing {missing!r} from {walked!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
