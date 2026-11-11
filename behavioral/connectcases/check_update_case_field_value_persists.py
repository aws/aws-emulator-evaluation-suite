"""update-case-field-value-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-case-field-value-persists"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateCase overwrites a field's value in place; GetCase reflects only the new
    value, never the stale one."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)

    case_id = _create_case(
        ctx,
        domain_id,
        template_id,
        [{"id": text_field, "value": {"stringValue": "v1"}}, *_required_system_fields(ctx)],
    )

    before = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": text_field}])
    before_value = {f["id"]: f["value"] for f in before["fields"]}[text_field]
    assert before_value == {"stringValue": "v1"}, (
        f"expected initial value v1, got {before_value!r}"
    )

    cc.update_case(
        domainId=domain_id,
        caseId=case_id,
        fields=[{"id": text_field, "value": {"stringValue": "v2"}}],
    )

    after = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": text_field}])
    value = {f["id"]: f["value"] for f in after["fields"]}[text_field]
    assert value == {"stringValue": "v2"}, f"expected updated value v2, got {value!r}"


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


def _create_customer_profile_arn(ctx):
    """CreateCase's `customer_id` field must resolve to a real Customer Profiles profile
    (AWS rejects a well-formed but non-existent ARN with `ValidationException`), so the
    domain and profile are created for real, not fabricated."""
    cp = ctx.client("customer-profiles")
    account = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-cc-profiles-")
    cp.create_domain(DomainName=domain_name, DefaultExpirationDays=30)
    ctx.on_cleanup(lambda: cp.delete_domain(DomainName=domain_name))
    profile_id = cp.create_profile(DomainName=domain_name)["ProfileId"]
    return f"arn:aws:profile:{ctx.region}:{account}:domains/{domain_name}/profiles/{profile_id}"


def _required_system_fields(ctx):
    """CreateCase always requires `title` and `customer_id`, independent of the
    template's own requiredFields."""
    return [
        {"id": "title", "value": {"stringValue": ctx.unique_name("sim2real-cc-case-")}},
        {"id": "customer_id", "value": {"stringValue": _create_customer_profile_arn(ctx)}},
    ]


def _create_case(ctx, domain_id, template_id, fields):
    cc = ctx.client("connectcases")
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=fields)["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
