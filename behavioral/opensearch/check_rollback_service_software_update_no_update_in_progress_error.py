"""rollback-service-software-update-no-update-in-progress-error."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rollback-service-software-update-no-update-in-progress-error"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackServiceSoftwareUpdate on a domain that is still being created fails with ValidationException
    and its exact message, and leaves ServiceSoftwareOptions.UpdateStatus unchanged.
    """
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=domain_name))

    before = client.describe_domain(DomainName=domain_name)["DomainStatus"]
    before_update_status = before["ServiceSoftwareOptions"]["UpdateStatus"]

    code, message = _error(lambda: client.rollback_service_software_update(DomainName=domain_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "A change/update is in progress. Please wait for it to complete before requesting another change."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected rollback attempt left the domain's service-software state
    # untouched -- it did not flip into a PENDING_UPDATE / rollback-in-progress state.
    after = client.describe_domain(DomainName=domain_name)["DomainStatus"]
    after_update_status = after["ServiceSoftwareOptions"]["UpdateStatus"]
    assert after_update_status == before_update_status, (
        f"expected UpdateStatus unchanged by the rejected rollback, "
        f"was {before_update_status!r}, now {after_update_status!r}"
    )

    # Positive control: an ordinary operation against the same domain still succeeds -- the
    # rejection is specific to "nothing to roll back", not a broken/unreachable domain.
    tag_list = client.list_tags(ARN=after["ARN"])["TagList"]
    assert isinstance(tag_list, list), f"expected list_tags to return a list, got {tag_list!r}"


def _domain_name(ctx) -> str:
    name = ctx.unique_name("sim2real-osd-rb-")
    return name.lower()[:28].rstrip("-")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
