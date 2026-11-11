"""related-item-connect-case-link."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "related-item-connect-case-link"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A ConnectCase related item appears in SearchRelatedItems of the source case with the target case's
    id, not in the target case's search; after deletion it leaves the source search and a second
    DeleteRelatedItem fails with the exact ResourceNotFoundException."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)
    # "title" is CreateCase's other required field: a reserved System-namespace field id
    # every Cases domain carries verbatim (confirmed via ListFields), not a generated UUID.
    title_field = "title"

    case_a = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": title_field, "value": {"stringValue": "case-a"}},
            {"id": text_field, "value": {"stringValue": "case-a"}},
        ],
    )
    case_b = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": title_field, "value": {"stringValue": "case-b"}},
            {"id": text_field, "value": {"stringValue": "case-b"}},
        ],
    )

    related_item_id = cc.create_related_item(
        domainId=domain_id,
        caseId=case_a,
        type="ConnectCase",
        content={"connectCase": {"caseId": case_b}},
    )["relatedItemId"]
    ctx.on_cleanup(
        lambda: _delete_related_item_idempotent(ctx, domain_id, case_a, related_item_id)
    )

    found = _poll_until(
        lambda: cc.search_related_items(domainId=domain_id, caseId=case_a)["relatedItems"],
        lambda items: any(i["relatedItemId"] == related_item_id for i in items),
        timeout_s=60.0,
        interval_s=3.0,
    )
    item = next(i for i in found if i["relatedItemId"] == related_item_id)
    assert item["type"] == "ConnectCase", f"expected type 'ConnectCase', got {item['type']!r}"
    assert item["content"]["connectCase"]["caseId"] == case_b, (
        f"expected linked caseId {case_b!r}, got {item['content']['connectCase']['caseId']!r}"
    )

    # the link is one-directional: case_b's own related items must not contain it
    other_items = cc.search_related_items(domainId=domain_id, caseId=case_b)["relatedItems"]
    assert all(i["relatedItemId"] != related_item_id for i in other_items), (
        f"one-directional link {related_item_id} leaked into case_b's related items: {other_items!r}"
    )

    cc.delete_related_item(domainId=domain_id, caseId=case_a, relatedItemId=related_item_id)
    _poll_until(
        lambda: cc.search_related_items(domainId=domain_id, caseId=case_a)["relatedItems"],
        lambda items: all(i["relatedItemId"] != related_item_id for i in items),
        timeout_s=60.0,
        interval_s=3.0,
    )
    delete_error = _client_error(
        lambda: cc.delete_related_item(
            domainId=domain_id, caseId=case_a, relatedItemId=related_item_id
        )
    )
    assert delete_error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted related item, "
        f"got {delete_error.get('Code')!r}"
    )
    expected_message = f"A related-item with id '{related_item_id}' could not be found."
    assert delete_error.get("Message") == expected_message, (
        f"expected double-delete message {expected_message!r}, got {delete_error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_related_item_idempotent(ctx, domain_id, case_id, related_item_id):
    cc = ctx.client("connectcases")
    try:
        cc.delete_related_item(domainId=domain_id, caseId=case_id, relatedItemId=related_item_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _create_case(ctx, domain_id, template_id, fields):
    cc = ctx.client("connectcases")
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=fields)["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
