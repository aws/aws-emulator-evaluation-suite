"""case-audit-events-track-create-and-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "case-audit-events-track-create-and-update"
GROUP = "telemetry"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCaseAuditEvents holds a Case.Created event and a later-or-equal Case.Updated event whose
    per-field diff carries the exact old ("v1") and new ("v2") values UpdateCase sent."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)

    case_id = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": "title", "value": {"stringValue": ctx.unique_name("sim2real-cc-case-")}},
            {"id": text_field, "value": {"stringValue": "v1"}},
        ],
    )
    cc.update_case(
        domainId=domain_id,
        caseId=case_id,
        fields=[{"id": text_field, "value": {"stringValue": "v2"}}],
    )

    events = _poll_until(
        lambda: cc.get_case_audit_events(domainId=domain_id, caseId=case_id)["auditEvents"],
        lambda evts: {"Case.Created", "Case.Updated"}.issubset({e["type"] for e in evts}),
        timeout_s=60.0,
        interval_s=3.0,
    )
    created_event = next(e for e in events if e["type"] == "Case.Created")
    updated_event = next(e for e in events if e["type"] == "Case.Updated")
    assert created_event["performedTime"] <= updated_event["performedTime"], (
        "Case.Created must be recorded before Case.Updated: "
        f"{created_event['performedTime']} > {updated_event['performedTime']}"
    )

    updated_fields = {f["eventFieldId"]: f for f in updated_event.get("fields", [])}
    assert text_field in updated_fields, (
        f"Case.Updated event must carry a field diff for {text_field}, "
        f"got fields {list(updated_fields)}"
    )
    changed = updated_fields[text_field]
    assert changed.get("oldValue", {}).get("stringValue") == "v1", (
        f"Case.Updated field diff oldValue must be the prior value 'v1', got {changed.get('oldValue')!r}"
    )
    assert changed.get("newValue", {}).get("stringValue") == "v2", (
        f"Case.Updated field diff newValue must be the new value 'v2', got {changed.get('newValue')!r}"
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


def _create_case(ctx, domain_id, template_id, fields):
    cc = ctx.client("connectcases")
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=fields)["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
