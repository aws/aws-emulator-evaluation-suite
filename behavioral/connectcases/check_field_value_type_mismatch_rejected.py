"""field-value-type-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "field-value-type-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCase rejects a field value whose union variant does not match the field's
    declared FieldType (a stringValue supplied for a Number field), creates no case, and
    supplying the matching doubleValue for the same field still succeeds."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    number_field = _create_field(ctx, domain_id, "Number", "number")
    template_id = _create_template(ctx, domain_id)
    title_field = _system_field_id(ctx, domain_id, "title")
    title_value = {"stringValue": ctx.unique_name("sim2real-cc-case-")}

    error = _client_error(
        lambda: cc.create_case(
            domainId=domain_id,
            templateId=template_id,
            fields=[
                {"id": title_field, "value": title_value},
                {"id": number_field, "value": {"stringValue": "42"}},
            ],
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected_message = f"Field '{number_field}' value should be a doubleValue"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    total_after_reject = cc.search_cases(domainId=domain_id)["totalCount"]
    assert total_after_reject == 0, f"a case must not have been created, totalCount={total_after_reject}"

    case_id = cc.create_case(
        domainId=domain_id,
        templateId=template_id,
        fields=[
            {"id": title_field, "value": title_value},
            {"id": number_field, "value": {"doubleValue": 42.0}},
        ],
        tags={"sim2real": "true"},
    )["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))

    got = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": number_field}])
    value = {f["id"]: f["value"] for f in got["fields"]}[number_field]
    assert value == {"doubleValue": 42.0}, f"expected the matching doubleValue to persist, got {value!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
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
    domain_resp = cc.create_domain(name=name)
    domain_id = domain_resp["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    cc.tag_resource(arn=domain_resp["domainArn"], tags={"sim2real": "true"})
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


def _system_field_id(ctx, domain_id, name):
    """CreateCase requires values for the domain's SYSTEM fields (e.g. `title`), which are
    provisioned automatically and are not something the check creates; look up the fieldId by
    name rather than guessing one."""
    cc = ctx.client("connectcases")
    for field in cc.list_fields(domainId=domain_id)["fields"]:
        if field["namespace"] == "System" and field["name"].lower() == name.lower():
            return field["fieldId"]
    raise AssertionError(f"no System field named {name!r} on domain {domain_id!r}")


def _create_field(ctx, domain_id, field_type, name_prefix="field"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name(f"sim2real-cc-{name_prefix}-")
    field_resp = cc.create_field(domainId=domain_id, name=name, type=field_type)
    field_id = field_resp["fieldId"]
    ctx.on_cleanup(lambda: cc.delete_field(domainId=domain_id, fieldId=field_id))
    cc.tag_resource(arn=field_resp["fieldArn"], tags={"sim2real": "true"})
    return field_id


def _create_template(ctx, domain_id, required_field_ids=None, rules=None, status="Active"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-template-")
    kwargs = {"domainId": domain_id, "name": name, "status": status}
    if required_field_ids:
        kwargs["requiredFields"] = [{"fieldId": fid} for fid in required_field_ids]
    if rules:
        kwargs["rules"] = rules
    template_resp = cc.create_template(**kwargs)
    template_id = template_resp["templateId"]
    ctx.on_cleanup(lambda: cc.delete_template(domainId=domain_id, templateId=template_id))
    cc.tag_resource(arn=template_resp["templateArn"], tags={"sim2real": "true"})
    return template_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
