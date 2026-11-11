"""attach-data-source-inactive-domain-state."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attach-data-source-inactive-domain-state"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachDataSource for a domain that is still being created returns PENDING; describe and a repeat
    attach return the same attachmentId, still PENDING, while the domain stays in creation.
    """
    osc = ctx.client("opensearch")

    app_name = ctx.unique_name("sim2real-app-")[:30].rstrip("-")
    app = osc.create_application(
        name=app_name, tagList=[{"Key": "sim2real", "Value": "attach-data-source-inactive-domain-state"}]
    )
    app_id = app["id"]

    def _cleanup_app():
        try:
            osc.detach_data_source(id=app_id, dataSourceArn=domain_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            osc.delete_application(id=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_app)

    domain_name = ctx.unique_name("sim2real-od-")[:28].rstrip("-")
    domain = osc.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "attach-data-source-inactive-domain-state"}],
    )
    domain_arn = domain["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))

    # The check holds the not-yet-active window itself: the domain it just created is still
    # being created. _assert_domain_still_creating brackets every PENDING read, so each one is
    # graded while the window is verifiably open, never on an assumed creation duration.
    _assert_domain_still_creating(osc, domain_name)
    first = osc.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    assert first["status"] == "PENDING", f"expected PENDING, got {first['status']!r}"
    attachment_id = first["attachmentId"]

    described = osc.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn)
    assert described["status"] == "PENDING", f"expected PENDING, got {described['status']!r}"
    assert described["attachmentId"] == attachment_id, (
        f"describe returned a different attachmentId ({described['attachmentId']!r}) "
        f"than the original attach response ({attachment_id!r})"
    )

    # Idempotent retry: re-attaching the same (id, dataSourceArn) pair must return the SAME
    # existing attachment rather than erroring or creating a second one.
    second = osc.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    assert second["attachmentId"] == attachment_id, (
        f"repeat attach returned a different attachmentId ({second['attachmentId']!r}) "
        f"than the original ({attachment_id!r}), implying a duplicate record was created"
    )
    assert second["status"] == "PENDING", f"expected PENDING on repeat attach, got {second['status']!r}"

    # Terminal read: independent of the mutating attach_data_source call, so the assertion
    # is not just the mutator echoing its own input back.
    redescribed = osc.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn)
    assert redescribed["attachmentId"] == attachment_id, (
        f"post-retry describe returned a different attachmentId ({redescribed['attachmentId']!r}) "
        f"than the original ({attachment_id!r})"
    )
    assert redescribed["status"] == "PENDING", (
        f"post-retry describe expected PENDING, got {redescribed['status']!r}"
    )
    _assert_domain_still_creating(osc, domain_name)


def _assert_domain_still_creating(osc, domain_name) -> None:
    status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
    assert status.get("Processing") is True and status.get("Endpoint") is None, (
        f"domain {domain_name} left its creating window while the check held it: "
        f"Processing={status.get('Processing')!r}, Endpoint={status.get('Endpoint')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
