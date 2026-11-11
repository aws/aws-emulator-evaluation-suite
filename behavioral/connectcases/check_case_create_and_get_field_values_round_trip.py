"""case-create-and-get-field-values-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "case-create-and-get-field-values-round-trip"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCase persists Text/Number/Boolean field values exactly, and GetCase returns
    the same values keyed by field ID along with the correct templateId."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)

    text_field = _create_field(ctx, domain_id, "Text", "text")
    number_field = _create_field(ctx, domain_id, "Number", "number")
    bool_field = _create_field(ctx, domain_id, "Boolean", "bool")

    template_id = _create_template(ctx, domain_id)

    # "title" is a system-defined field present on every domain (fixed field id "title",
    # per every domain's ListFields); CreateCase rejects with ValidationException
    # "Field(s) title are required" if it is omitted, regardless of the template's
    # declared requiredFields.
    fields = [
        {"id": "title", "value": {"stringValue": "hello-case-title"}},
        {"id": text_field, "value": {"stringValue": "hello-case"}},
        {"id": number_field, "value": {"doubleValue": 3.5}},
        {"id": bool_field, "value": {"booleanValue": True}},
    ]
    case_id = _create_case(ctx, domain_id, template_id, fields)

    got = cc.get_case(
        domainId=domain_id,
        caseId=case_id,
        fields=[{"id": "title"}, {"id": text_field}, {"id": number_field}, {"id": bool_field}],
    )
    assert got["templateId"] == template_id, f"expected templateId {template_id!r}, got {got['templateId']!r}"
    values = {f["id"]: f["value"] for f in got["fields"]}
    assert values["title"] == {"stringValue": "hello-case-title"}, f"title field: {values['title']!r}"
    assert values[text_field] == {"stringValue": "hello-case"}, f"text field: {values[text_field]!r}"
    assert values[number_field] == {"doubleValue": 3.5}, f"number field: {values[number_field]!r}"
    assert values[bool_field] == {"booleanValue": True}, f"boolean field: {values[bool_field]!r}"


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
