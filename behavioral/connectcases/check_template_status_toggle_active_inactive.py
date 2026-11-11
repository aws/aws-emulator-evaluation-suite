"""template-status-toggle-active-inactive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-status-toggle-active-inactive"
GROUP = "state"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTemplate toggles status Active -> Inactive -> Active, with GetTemplate and ListTemplates(status)
    agreeing at each step; after DeleteTemplate, GetTemplate returns deleted=True, neither listing holds
    it, and UpdateTemplate fails with the exact ResourceNotFoundException."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)

    name = ctx.unique_name("sim2real-cc-template-")
    template_id = cc.create_template(domainId=domain_id, name=name, status="Active")["templateId"]
    ctx.on_cleanup(lambda: _cleanup_template(cc, domain_id, template_id))

    created = cc.get_template(domainId=domain_id, templateId=template_id)
    assert created["status"] == "Active", f"expected Active on create, got {created['status']!r}"
    assert template_id in _listed_ids(cc, domain_id, "Active"), (
        "a freshly created Active template is missing from ListTemplates(status=Active)"
    )

    cc.update_template(domainId=domain_id, templateId=template_id, status="Inactive")
    updated = cc.get_template(domainId=domain_id, templateId=template_id)
    assert updated["status"] == "Inactive", f"expected Inactive, got {updated['status']!r}"
    assert template_id not in _listed_ids(cc, domain_id, "Active"), (
        "template still listed under status=Active after toggling to Inactive"
    )
    assert template_id in _listed_ids(cc, domain_id, "Inactive"), (
        "template missing from ListTemplates(status=Inactive) after toggling to Inactive"
    )

    # The check's own name claims a toggle, not a one-way transition: prove the reverse leg too.
    cc.update_template(domainId=domain_id, templateId=template_id, status="Active")
    restored = cc.get_template(domainId=domain_id, templateId=template_id)
    assert restored["status"] == "Active", f"expected toggle back to Active, got {restored['status']!r}"
    assert template_id in _listed_ids(cc, domain_id, "Active"), (
        "template missing from ListTemplates(status=Active) after toggling back to Active"
    )
    assert template_id not in _listed_ids(cc, domain_id, "Inactive"), (
        "template still listed under status=Inactive after toggling back to Active"
    )

    cc.delete_template(domainId=domain_id, templateId=template_id)
    after_delete = cc.get_template(domainId=domain_id, templateId=template_id)
    assert after_delete.get("deleted") is True, (
        f"expected deleted=True from GetTemplate after DeleteTemplate, got {after_delete!r}"
    )
    assert template_id not in _listed_ids(cc, domain_id, "Active"), (
        "deleted template still listed under status=Active"
    )
    assert template_id not in _listed_ids(cc, domain_id, "Inactive"), (
        "deleted template still listed under status=Inactive"
    )
    error = _client_error(
        lambda: cc.update_template(domainId=domain_id, templateId=template_id, status="Active")
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"UpdateTemplate on a deleted template returned {error.get('Code')!r}, expected "
        f"'ResourceNotFoundException'"
    )
    assert error.get("Message") == "Requested resource not found.", (
        f"UpdateTemplate on a deleted template returned message {error.get('Message')!r}, expected "
        f"'Requested resource not found.'"
    )


def _listed_ids(cc, domain_id, status):
    ids = set()
    token = None
    while True:
        kwargs = {"domainId": domain_id, "status": [status]}
        if token:
            kwargs["nextToken"] = token
        page = cc.list_templates(**kwargs)
        ids.update(t["templateId"] for t in page.get("templates", []))
        token = page.get("nextToken")
        if not token:
            return ids


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cleanup_template(cc, domain_id, template_id):
    try:
        cc.delete_template(domainId=domain_id, templateId=template_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
