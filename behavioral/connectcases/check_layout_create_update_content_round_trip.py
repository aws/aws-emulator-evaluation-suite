"""layout-create-update-content-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layout-create-update-content-round-trip"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLayout returns exactly the content CreateLayout and then UpdateLayout stored; after DeleteLayout it
    still returns the layout with deleted=True, ListLayouts omits it, and UpdateLayout fails with the
    exact ResourceNotFoundException."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    field_a = _create_field(ctx, domain_id, "Text", "layout-a")
    field_b = _create_field(ctx, domain_id, "Number", "layout-b")

    name = ctx.unique_name("sim2real-cc-layout-")
    initial_content = {
        "basic": {
            "topPanel": {"sections": [{"fieldGroup": {"fields": [{"id": field_a}]}}]},
        }
    }
    layout_id = cc.create_layout(domainId=domain_id, name=name, content=initial_content)["layoutId"]

    created = cc.get_layout(domainId=domain_id, layoutId=layout_id)
    top_fields = created["content"]["basic"]["topPanel"]["sections"][0]["fieldGroup"]["fields"]
    assert top_fields == [{"id": field_a}], f"expected topPanel fields [{{'id': field_a}}], got {top_fields!r}"
    more_info = created["content"]["basic"].get("moreInfo")
    assert more_info == {"sections": []}, (
        f"expected an unspecified moreInfo section to come back present but empty, got {more_info!r}"
    )

    updated_content = {
        "basic": {
            "topPanel": {"sections": [{"fieldGroup": {"fields": [{"id": field_a}]}}]},
            "moreInfo": {"sections": [{"fieldGroup": {"fields": [{"id": field_b}]}}]},
        }
    }
    cc.update_layout(domainId=domain_id, layoutId=layout_id, content=updated_content)

    updated = cc.get_layout(domainId=domain_id, layoutId=layout_id)
    more_info_fields = updated["content"]["basic"]["moreInfo"]["sections"][0]["fieldGroup"]["fields"]
    assert more_info_fields == [{"id": field_b}], f"expected moreInfo fields [{{'id': field_b}}], got {more_info_fields!r}"
    top_fields_after = updated["content"]["basic"]["topPanel"]["sections"][0]["fieldGroup"]["fields"]
    assert top_fields_after == [{"id": field_a}], (
        f"update must not blend versions: expected topPanel fields [{{'id': field_a}}] to survive, "
        f"got {top_fields_after!r}"
    )

    cc.delete_layout(domainId=domain_id, layoutId=layout_id)

    after_delete = cc.get_layout(domainId=domain_id, layoutId=layout_id)
    assert after_delete["deleted"] is True, (
        f"expected GetLayout on a deleted layout to report deleted=True, got {after_delete.get('deleted')!r}"
    )

    update_error = _client_error(
        lambda: cc.update_layout(domainId=domain_id, layoutId=layout_id, content=updated_content)
    )
    assert update_error.get("Code") == "ResourceNotFoundException", (
        f"expected UpdateLayout on a deleted layout to return ResourceNotFoundException, "
        f"got {update_error.get('Code')!r}"
    )
    assert update_error.get("Message") == "Requested resource not found.", (
        f"expected UpdateLayout message 'Requested resource not found.', got {update_error.get('Message')!r}"
    )

    remaining_ids = _poll_until(
        lambda: [entry["layoutId"] for entry in cc.list_layouts(domainId=domain_id)["layouts"]],
        lambda ids: layout_id not in ids,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert layout_id not in remaining_ids, (
        f"expected the deleted layout to drop out of ListLayouts, still present in {remaining_ids!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
