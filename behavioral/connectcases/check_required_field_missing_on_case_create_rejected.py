"""required-field-missing-on-case-create-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "required-field-missing-on-case-create-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCase rejects a request that omits a value for a field the template marks
    required, leaves no case behind, while supplying the required field succeeds."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    required_field = _create_field(ctx, domain_id, "Text", "required")
    template_id = _create_template(ctx, domain_id, required_field_ids=[required_field])
    title_field = _system_field_id(ctx, domain_id, "title")
    title_value = {"id": title_field, "value": {"stringValue": ctx.unique_name("sim2real-cc-title-")}}

    error = _client_error(
        lambda: cc.create_case(domainId=domain_id, templateId=template_id, fields=[title_value])
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected_message = f"Field value is not provided for a required field: {required_field}"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    total_after_reject = cc.search_cases(domainId=domain_id)["totalCount"]
    assert total_after_reject == 0, f"a case must not have been created, totalCount={total_after_reject}"

    case_id = cc.create_case(
        domainId=domain_id,
        templateId=template_id,
        fields=[title_value, {"id": required_field, "value": {"stringValue": "present"}}],
    )["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))

    total_after_success = _poll_until(
        lambda: cc.search_cases(domainId=domain_id)["totalCount"],
        lambda n: n == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert total_after_success == 1, (
        f"supplying the required field must let the case appear at an independent read, "
        f"got totalCount={total_after_success}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
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


def _system_field_id(ctx, domain_id, name):
    """Every domain is provisioned with a fixed set of System-namespace fields (e.g. the case
    title) that CreateCase requires regardless of the template's own requiredFields — find the
    one named `name` rather than assuming an id."""
    cc = ctx.client("connectcases")
    token = None
    while True:
        kwargs = {"domainId": domain_id}
        if token:
            kwargs["nextToken"] = token
        page = cc.list_fields(**kwargs)
        for field in page["fields"]:
            if field["namespace"] == "System" and field["name"].lower() == name.lower():
                return field["fieldId"]
        token = page.get("nextToken")
        if not token:
            raise AssertionError(f"no System field named {name!r} found in domain {domain_id!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
