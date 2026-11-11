"""describe-data-source-attachment-disabled-when-feature-off."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-data-source-attachment-disabled-when-feature-off"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDataSourceAttachment fails with ResourceNotFoundException and its exact message for an
    Elasticsearch-engine domain that has no attachment and for a domain that does not exist, while an
    attached ARN describes as PENDING or ATTACHED.
    """
    os_client = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    domain_name = _short_name(ctx, "sim2real-legacy-")
    domain_resp = os_client.create_domain(
        DomainName=domain_name,
        EngineVersion="Elasticsearch_7.10",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: os_client.delete_domain(DomainName=domain_name))
    domain_arn = domain_resp["DomainStatus"]["ARN"]
    _wait_domain_visible(os_client, domain_name)

    app_name = _short_name(ctx, "sim2real-app-", max_len=30)
    app_id = os_client.create_application(name=app_name)["id"]
    ctx.on_cleanup(lambda: _delete_application(os_client, app_id))
    _wait_application_active(os_client, app_id)

    # Positive control: AttachDataSource against a well-formed ARN for a domain that does not
    # exist yet is documented to be accepted immediately (status PENDING, completing
    # automatically once both sides become active) -- this is a real, present attachment
    # record, not a fabricated one. A PENDING attachment cannot be detached (DetachDataSource
    # documents a ConflictException for that state), so deleting the application above
    # (cascading cleanup) removes it instead of an explicit detach.
    pending_domain_name = _short_name(ctx, "sim2real-pending-")
    pending_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{pending_domain_name}"
    try:
        os_client.attach_data_source(id=app_id, dataSourceArn=pending_arn)
    except ClientError as e:
        raise AssertionError(
            f"expected AttachDataSource against a well-formed, not-yet-real domain ARN to be "
            f"accepted (PENDING), got {e.response.get('Error', {}).get('Code')}"
        ) from e

    # Independent read: DescribeDataSourceAttachment is a different operation than the
    # AttachDataSource call that created the record, and it must report the record as real.
    positive = os_client.describe_data_source_attachment(id=app_id, dataSourceArn=pending_arn)
    assert positive["status"] in ("PENDING", "ATTACHED"), (
        f"expected the attachment just created to describe as PENDING/ATTACHED, "
        f"got {positive.get('status')!r}"
    )

    # Negative A: a domain that genuinely exists, with an engine that can never be an eligible
    # attachment target, but that was never attached -- no attachment record exists for it.
    unattached_code, unattached_message = _error(
        lambda: os_client.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn)
    )
    assert unattached_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a real, never-attached, ineligible-engine "
        f"domain (no attachment record exists for it -- engine eligibility is not checked "
        f"ahead of the attachment-record lookup), got {unattached_code}"
    )
    expected_unattached = (
        f"Data source attachment not found for application {app_id} and data source {domain_arn}"
    )
    assert unattached_message == expected_unattached, (
        f"expected message {expected_unattached!r}, got {unattached_message!r}"
    )

    # Negative B: a domain that does not exist at all, also never attached.
    missing_arn = domain_arn.rsplit("/", 1)[0] + "/" + _short_name(ctx, "sim2real-nope-")
    missing_code, missing_message = _error(
        lambda: os_client.describe_data_source_attachment(id=app_id, dataSourceArn=missing_arn)
    )
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent domain ARN, "
        f"got {missing_code}"
    )
    expected_missing = (
        f"Data source attachment not found for application {app_id} and data source {missing_arn}"
    )
    assert missing_message == expected_missing, (
        f"expected message {expected_missing!r}, got {missing_message!r}"
    )

    # Both "no attachment record" cases collapse to the SAME code -- proving
    # ResourceNotFoundException here tracks "no attachment record", not "this domain doesn't
    # exist" (which would have separated the real-but-ineligible domain from the fictional
    # one), and that code is distinct from the real attachment record proven above.
    assert unattached_code == missing_code == "ResourceNotFoundException", (
        f"the ineligible-engine domain and the fictional domain must collapse to the same "
        f"not-found code, got {unattached_code!r} vs {missing_code!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _short_name(ctx, prefix, max_len=28):
    name = ctx.unique_name(prefix)[:max_len]
    if not name[-1].isalnum():
        name = name[:-1] + "0"
    return name


def _wait_domain_visible(client, domain_name, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_domain(DomainName=domain_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became visible within {timeout_s}s")


def _wait_application_active(client, app_id, timeout_s=300.0, interval_s=3.0):
    """Bounded poll until the application leaves CREATING; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_application(id=app_id).get("status")
        if last != "CREATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never left CREATING within {timeout_s}s (last: {last})")


def _delete_application(client, app_id, timeout_s=600.0, interval_s=10.0):
    """Teardown: retry while an operation on the application is still in progress; an
    application that is already gone counts as deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_application(id=app_id)
            return
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
