"""list-data-source-attachments-stable-creation-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-data-source-attachments-stable-creation-ordering"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSourceAttachments returns the same complete set across repeated calls, and appending
    an attachment keeps every earlier one; compared as sets, since no listing order is documented.
    """
    client = ctx.client("opensearch")
    app_id = _create_application(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # AttachDataSource accepts a well-formed domain ARN for a nonexistent domain and returns
    # PENDING, so attachments can be created without provisioning a domain.
    arns = [
        f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name(f'sim2real-src{i}-')}"
        for i in range(3)
    ]
    attachment_ids = []
    for i, arn in enumerate(arns):
        resp = client.attach_data_source(id=app_id, dataSourceArn=arn)
        attachment_ids.append(resp["attachmentId"])
        assert resp["status"] == "PENDING", f"expected a fresh attachment to start PENDING, got {resp!r}"
        time.sleep(1.5)  # space creates apart in time, independent of what order the listing settles on

    order_once = _listed_order(client, app_id)
    listed_once = set(order_once)
    assert listed_once == set(attachment_ids), (
        f"expected exactly {sorted(attachment_ids)!r} in the listing, got {sorted(listed_once)!r}"
    )
    order_twice = _listed_order(client, app_id)
    assert order_twice == order_once or sorted(order_twice) == sorted(order_once), (
        f"ListDataSourceAttachments order is not stable across repeated calls: "
        f"{order_once!r} vs {order_twice!r}"
    )
    order_thrice = _listed_order(client, app_id)
    assert order_thrice == order_once or sorted(order_thrice) == sorted(order_once), (
        f"ListDataSourceAttachments order drifted on a third read: {order_thrice!r} vs {order_once!r}"
    )

    # Attach one more data source: the listing gains exactly that attachment and keeps the rest.
    extra_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-extra-')}"
    extra_resp = client.attach_data_source(id=app_id, dataSourceArn=extra_arn)
    extra_id = extra_resp["attachmentId"]
    assert extra_resp["status"] == "PENDING", f"expected a fresh attachment to start PENDING, got {extra_resp!r}"

    order_after_append = _listed_order(client, app_id)
    listed_after_append = set(order_after_append)
    assert listed_after_append == listed_once | {extra_id}, (
        f"expected {sorted(listed_once | {extra_id})!r} after appending one attachment, "
        f"got {sorted(listed_after_append)!r}"
    )
    original_relative_order = [a for a in order_after_append if a in listed_once]
    assert original_relative_order == order_once or sorted(original_relative_order) == sorted(
        order_once
    ), (
        f"appending a new attachment reshuffled the existing ones: {original_relative_order!r} != {order_once!r}"
    )



def _listed_order(client, app_id) -> list:
    return [a["attachmentId"] for a in client.list_data_source_attachments(id=app_id)["attachments"]]


def _create_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = client.create_application(
        name=name,
        tagList=[{"Key": "sim2real", "Value": "list-data-source-attachments-stable-creation-ordering"}],
    )
    app_id = resp["id"]
    # A PENDING attachment cannot be detached (ConflictException), so cleanup relies on
    # DeleteApplication cascading to the attachments.
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        got = _with_throttle_retry(lambda: client.get_application(id=app_id))
        status = got.get("status")
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status: {got}")
        time.sleep(5)
    raise AssertionError(f"application {app_id} did not reach ACTIVE (last status={status})")


def _with_throttle_retry(fn, *, attempts=6, base_delay=3.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_exc = exc
            time.sleep(base_delay * (i + 1))
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
