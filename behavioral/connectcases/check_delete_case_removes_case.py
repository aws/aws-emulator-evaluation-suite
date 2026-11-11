"""delete-case-removes-case."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-case-removes-case"
GROUP = "state"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteCase permanently removes the case: a subsequent GetCase fails with
    ResourceNotFoundException and SearchCases totalCount drops back to zero."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")
    template_id = _create_template(ctx, domain_id)

    case_id = cc.create_case(
        domainId=domain_id,
        templateId=template_id,
        fields=[
            {"id": "title", "value": {"stringValue": "sim2real-cc-case-to-delete"}},
            {"id": text_field, "value": {"stringValue": "to-delete"}},
        ],
    )["caseId"]

    # confirm it exists before deletion
    got = cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": text_field}])
    assert got["templateId"] == template_id, f"expected templateId {template_id!r}, got {got['templateId']!r}"

    total_before = _poll_until(
        lambda: cc.search_cases(domainId=domain_id)["totalCount"],
        lambda n: n == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert total_before == 1, f"expected SearchCases totalCount 1 before delete, got {total_before!r}"

    cc.delete_case(domainId=domain_id, caseId=case_id)

    expected_message = f"A case with id '{case_id}' could not be found."
    error = _client_error(lambda: cc.get_case(domainId=domain_id, caseId=case_id, fields=[{"id": text_field}]))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')!r}"
    )
    assert error.get("Message") == expected_message, (
        f"expected GetCase message {expected_message!r}, got {error.get('Message')!r}"
    )

    mutation_error = _client_error(
        lambda: cc.update_case(
            domainId=domain_id,
            caseId=case_id,
            fields=[{"id": text_field, "value": {"stringValue": "post-delete-update"}}],
        )
    )
    assert mutation_error.get("Code") == "ResourceNotFoundException", (
        f"expected UpdateCase on a deleted case to fail with ResourceNotFoundException, "
        f"got {mutation_error.get('Code')!r}"
    )
    assert mutation_error.get("Message") == expected_message, (
        f"expected UpdateCase message {expected_message!r}, got {mutation_error.get('Message')!r}"
    )

    total_after = _poll_until(
        lambda: cc.search_cases(domainId=domain_id)["totalCount"],
        lambda n: n == 0,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert total_after == 0, f"expected SearchCases totalCount 0 after delete, got {total_after!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
