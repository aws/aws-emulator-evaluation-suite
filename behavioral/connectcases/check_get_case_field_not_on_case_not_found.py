"""get-case-field-not-on-case-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-case-field-not-on-case-not-found"
GROUP = "overly-permissive"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCase returns an empty `fields` for a schema field never set on the case, rejects a field id not
    in the domain schema with the exact ValidationException, and returns the stored value of a set field."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    field_set = _create_field(ctx, domain_id, "Text", "set")
    field_unset = _create_field(ctx, domain_id, "Text", "unset")
    template_id = _create_template(ctx, domain_id)

    case_id = _create_case(
        ctx,
        domain_id,
        template_id,
        [
            {"id": "title", "value": {"stringValue": ctx.unique_name("sim2real-cc-case-")}},
            {"id": field_set, "value": {"stringValue": "present"}},
        ],
    )

    got_unset = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": field_unset}])
    assert got_unset["fields"] == [], (
        f"expected an in-schema-but-unset field to be silently omitted, "
        f"got fields={got_unset['fields']!r}"
    )

    field_out_of_schema = ctx.unique_name("sim2real-cc-missing-field-")
    error = _client_error(
        lambda: cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": field_out_of_schema}])
    )
    assert error.get("Code") == "ValidationException", (
        f"expected a field ID missing from the domain schema entirely to be rejected with "
        f"ValidationException (distinct from the silent omission above), got {error.get('Code')!r}"
    )
    expected_message = f"Unknown field Ids: {field_out_of_schema}"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    got_set = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": field_set}])
    values = {f["id"]: f["value"] for f in got_set["fields"]}
    assert values[field_set] == {"stringValue": "present"}, (
        f"expected field {field_set!r} to carry its set value, got {values.get(field_set)!r}"
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


def _create_case(ctx, domain_id, template_id, fields):
    cc = ctx.client("connectcases")
    case_id = cc.create_case(domainId=domain_id, templateId=template_id, fields=fields)["caseId"]
    ctx.on_cleanup(lambda: cc.delete_case(domainId=domain_id, caseId=case_id))
    return case_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
