"""namespace-create-get-list-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-create-get-list-roundtrip"
GROUP = "control-plane"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataLakeNamespace's returned namespace matches GetDataLakeNamespace and appears in
    ListDataLakeNamespaces; once deleted, it is gone from both the independent reader and the
    list, and a mutation against the dead name is rejected."""
    # AWS Supply Chain's CreateInstance depends on Amazon Connect Decisions, which is not available
    # in every region (observed on real AWS: a deterministic ValidationException in us-west-2 —
    # "Amazon Connect Decisions is not supported in us-west-2"). Pinned per ctx.client's own region
    # override, the same idiom used for ACM/CloudFront's us-east-1-only control planes.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _dl_name(ctx, "ns")

    created = sc.create_data_lake_namespace(
        instanceId=instance_id,
        name=ns_name,
        description="sim2real namespace",
        tags={"sim2real": "true"},
    )["namespace"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )

    assert created["name"] == ns_name, f"expected name {ns_name!r}, got {created.get('name')!r}"
    assert created["description"] == "sim2real namespace", (
        f"expected description 'sim2real namespace', got {created.get('description')!r}"
    )
    assert created["arn"], f"expected a non-empty arn, got {created.get('arn')!r}"

    fetched = sc.get_data_lake_namespace(instanceId=instance_id, name=ns_name)["namespace"]
    assert fetched["name"] == ns_name, f"expected name {ns_name!r}, got {fetched.get('name')!r}"
    assert fetched["arn"] == created["arn"], (
        f"expected arn {created['arn']!r} from the independent read, got {fetched.get('arn')!r}"
    )
    assert fetched["description"] == "sim2real namespace", (
        f"expected description 'sim2real namespace', got {fetched.get('description')!r}"
    )

    names = _list_namespace_names(sc, instance_id)
    assert ns_name in names, f"{ns_name} not found in namespace list: {names}"

    # The namespace is deleted in-check (cleanup would otherwise be the only delete) so its
    # absence can be asserted: gone from an independent read, gone from the list, and no longer
    # a valid target for a mutation.
    sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name)

    gone_message = f"Namespace {ns_name} not exist"
    code_after_delete, message_after_delete = _error(
        lambda: sc.get_data_lake_namespace(instanceId=instance_id, name=ns_name)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted namespace, got {code_after_delete}"
    )
    assert message_after_delete == gone_message, f"expected {gone_message!r}, got {message_after_delete!r}"

    names_after_delete = _poll_until(
        lambda: _list_namespace_names(sc, instance_id),
        lambda ns: ns_name not in ns,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert ns_name not in names_after_delete, (
        f"{ns_name} still in namespace list after delete: {names_after_delete}"
    )

    code_update_after_delete, message_update_after_delete = _error(
        lambda: sc.update_data_lake_namespace(
            instanceId=instance_id, name=ns_name, description="post-delete-update"
        )
    )
    assert code_update_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating the deleted namespace, got {code_update_after_delete}"
    )
    assert message_update_after_delete == gone_message, (
        f"expected {gone_message!r}, got {message_update_after_delete!r}"
    )


def _dl_name(ctx, kind):
    """Sanitize ctx.unique_name output to satisfy the ^[a-z0-9_]+$ data-lake naming pattern."""
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _list_namespace_names(sc, instance_id):
    names = set()
    next_token = None
    while True:
        kwargs = {"instanceId": instance_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = sc.list_data_lake_namespaces(**kwargs)
        names.update(n["name"] for n in page["namespaces"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return names


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": "true"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
