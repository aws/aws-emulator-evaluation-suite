"""search-all-related-items-across-cases."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-all-related-items-across-cases"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchAllRelatedItems is a domain-wide search: related items created on two
    different cases both surface in the same call, each tagged with its own caseId."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)

    case_a = _create_case(
        ctx, domain_id, template_id, [{"id": text_field, "value": {"stringValue": "case-a"}}]
    )
    case_b = _create_case(
        ctx, domain_id, template_id, [{"id": text_field, "value": {"stringValue": "case-b"}}]
    )

    item_a = cc.create_related_item(
        domainId=domain_id,
        caseId=case_a,
        type="Comment",
        content={"comment": {"body": "note on case a", "contentType": "Text/Plain"}},
    )["relatedItemId"]
    ctx.on_cleanup(
        lambda: cc.delete_related_item(domainId=domain_id, caseId=case_a, relatedItemId=item_a)
    )
    item_b = cc.create_related_item(
        domainId=domain_id,
        caseId=case_b,
        type="Comment",
        content={"comment": {"body": "note on case b", "contentType": "Text/Plain"}},
    )["relatedItemId"]
    ctx.on_cleanup(
        lambda: cc.delete_related_item(domainId=domain_id, caseId=case_b, relatedItemId=item_b)
    )

    found = _poll_until(
        lambda: cc.search_all_related_items(domainId=domain_id)["relatedItems"],
        lambda items: {item_a, item_b}.issubset({i["relatedItemId"] for i in items}),
        timeout_s=90.0,
        interval_s=4.0,
    )
    by_id = {i["relatedItemId"]: i for i in found}
    assert by_id[item_a]["caseId"] == case_a, (
        f"expected item_a caseId {case_a!r}, got {by_id[item_a]['caseId']!r}"
    )
    assert by_id[item_b]["caseId"] == case_b, (
        f"expected item_b caseId {case_b!r}, got {by_id[item_b]['caseId']!r}"
    )


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


def _title_field_id(ctx, domain_id):
    cc = ctx.client("connectcases")
    next_token = None
    while True:
        kwargs = {"domainId": domain_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = cc.list_fields(**kwargs)
        for field in resp["fields"]:
            if field["namespace"] == "System" and field["name"] == "Title":
                return field["fieldId"]
        next_token = resp.get("nextToken")
        if not next_token:
            break
    raise AssertionError(f"domain {domain_id!r} has no system field named 'Title'")


def _create_case(ctx, domain_id, template_id, fields, title="sim2real case"):
    cc = ctx.client("connectcases")
    all_fields = [{"id": _title_field_id(ctx, domain_id), "value": {"stringValue": title}}, *fields]
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=all_fields)["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
