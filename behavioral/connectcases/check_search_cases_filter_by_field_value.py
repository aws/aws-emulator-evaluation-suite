"""search-cases-filter-by-field-value."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-cases-filter-by-field-value"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchCases with an `equalTo` field filter returns exactly the case matching that
    value and excludes a sibling case with a different value for the same field."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    category_field = _create_field(ctx, domain_id, "Text", "category")
    template_id = _create_template(ctx, domain_id)
    title_field = _title_field_id(ctx, domain_id)

    case_billing = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": title_field, "value": {"stringValue": "case-billing"}},
            {"id": category_field, "value": {"stringValue": "billing"}},
        ],
    )
    case_technical = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": title_field, "value": {"stringValue": "case-technical"}},
            {"id": category_field, "value": {"stringValue": "technical"}},
        ],
    )

    def _search():
        return cc.search_cases(
            domainId=domain_id,
            filter={"field": {"equalTo": {"id": category_field, "value": {"stringValue": "billing"}}}},
        )

    result = _poll_until(
        _search,
        lambda r: r["totalCount"] == 1 and any(c["caseId"] == case_billing for c in r["cases"]),
        timeout_s=90.0,
        interval_s=4.0,
    )
    case_ids = {c["caseId"] for c in result["cases"]}
    assert case_ids == {case_billing}, f"expected only billing case, got {case_ids}"
    assert case_technical not in case_ids, (
        f"technical case {case_technical} leaked into a billing-only filter result {case_ids}"
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


def _title_field_id(ctx, domain_id):
    cc = ctx.client("connectcases")
    fields = cc.list_fields(domainId=domain_id)["fields"]
    for f in fields:
        if f["namespace"] == "System" and f["name"].lower() == "title":
            return f["fieldId"]
    raise AssertionError(f"no System 'title' field found on domain {domain_id!r}: {fields!r}")


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
