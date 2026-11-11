"""related-item-type-content-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "related-item-type-content-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateRelatedItem rejects a request whose declared `type` does not match the
    variant set on `content` (declaring Contact but supplying comment content), leaves
    no related item behind, while a correctly matched Comment request still succeeds."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)
    case_id = _create_case(
        ctx, domain_id, template_id, [{"id": text_field, "value": {"stringValue": "mismatch-case"}}]
    )

    error = _client_error(
        lambda: cc.create_related_item(
            domainId=domain_id,
            caseId=case_id,
            type="Contact",
            content={"comment": {"body": "wrong content for declared type", "contentType": "Text/Plain"}},
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected_message = "CONTACT type was specified with a mismatched related-item content."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    items = cc.search_related_items(domainId=domain_id, caseId=case_id)["relatedItems"]
    assert items == [], f"mismatched related item should not have been created, found {items!r}"

    ok_id = cc.create_related_item(
        domainId=domain_id,
        caseId=case_id,
        type="Comment",
        content={"comment": {"body": "correctly typed comment", "contentType": "Text/Plain"}},
    )["relatedItemId"]
    ctx.on_cleanup(
        lambda: cc.delete_related_item(domainId=domain_id, caseId=case_id, relatedItemId=ok_id)
    )

    found = _poll_until(
        lambda: cc.search_related_items(domainId=domain_id, caseId=case_id)["relatedItems"],
        lambda items: any(i["relatedItemId"] == ok_id for i in items),
        timeout_s=60.0,
        interval_s=3.0,
    )
    item = next(i for i in found if i["relatedItemId"] == ok_id)
    assert item["type"] == "Comment", f"expected type Comment, got {item['type']!r}"
    assert item["content"]["comment"]["body"] == "correctly typed comment", (
        f"expected body 'correctly typed comment', got {item['content']['comment']['body']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


def _create_active_domain(ctx):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    domain_id = cc.create_domain(name=name)["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


def _create_field(ctx, domain_id, field_type, name_prefix="field"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name(f"sim2real-cc-{name_prefix}-")
    field_id = cc.create_field(domainId=domain_id, name=name, type=field_type)["fieldId"]
    ctx.on_cleanup(lambda: cc.delete_field(domainId=domain_id, fieldId=field_id))
    return field_id


def _create_template(ctx, domain_id, required_field_ids=None, rules=None, status="Active"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-template-")
    kwargs = {"domainId": domain_id, "name": name, "status": status}
    if required_field_ids:
        kwargs["requiredFields"] = [{"fieldId": fid} for fid in required_field_ids]
    if rules:
        kwargs["rules"] = rules
    template_id = cc.create_template(**kwargs)["templateId"]
    ctx.on_cleanup(lambda: cc.delete_template(domainId=domain_id, templateId=template_id))
    return template_id


def _system_field_id(ctx, domain_id, name):
    cc = ctx.client("connectcases")
    system_fields = [f for f in cc.list_fields(domainId=domain_id)["fields"] if f["namespace"] == "System"]
    for f in system_fields:
        if f["name"].lower() == name.lower():
            return f["fieldId"]
    raise AssertionError(f"no System field named {name!r} in domain {domain_id!r}, system fields={system_fields!r}")


def _create_case(ctx, domain_id, template_id, fields):
    cc = ctx.client("connectcases")
    title_field_id = _system_field_id(ctx, domain_id, "title")
    title_field = {"id": title_field_id, "value": {"stringValue": ctx.unique_name("sim2real-cc-case-")}}
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=[title_field, *fields])["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
