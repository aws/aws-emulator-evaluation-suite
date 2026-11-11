"""op-contract-modify-traffic-mirror-filter-network-services."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-traffic-mirror-filter-network-services"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTrafficMirrorFilterNetworkServices: adding/removing 'amazon-dns' is
    reflected on the filter's NetworkServices list, and an unrecognized service name is
    rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmf-")
    filt = ec2.create_traffic_mirror_filter(
        Description="behavioral test filter", TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]
    filter_id = filt["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id)))
    assert filt.get("NetworkServices", []) == [], filt

    # success path: add then remove the amazon-dns network service. Each half is
    # confirmed by an independent DescribeTrafficMirrorFilters read, not just the
    # mutating call's own echoed response.
    added = ec2.modify_traffic_mirror_filter_network_services(
        TrafficMirrorFilterId=filter_id, AddNetworkServices=["amazon-dns"]
    )["TrafficMirrorFilter"]
    assert added["NetworkServices"] == ["amazon-dns"], added

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    assert described.get("NetworkServices", []) == ["amazon-dns"], described

    removed = ec2.modify_traffic_mirror_filter_network_services(
        TrafficMirrorFilterId=filter_id, RemoveNetworkServices=["amazon-dns"]
    )["TrafficMirrorFilter"]
    assert removed.get("NetworkServices", []) == [], removed

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    assert described.get("NetworkServices", []) == [], described

    # error boundary: not a recognized network service
    err, err_msg = _client_error(
        lambda: ec2.modify_traffic_mirror_filter_network_services(
            TrafficMirrorFilterId=filter_id, AddNetworkServices=["not-a-real-service"]
        )
    )
    assert err == "InvalidParameterValue", err
    assert err_msg == "'not-a-real-service' is not a valid network service", err_msg

    # effect-absent: the rejected call must not have mutated filter state, confirmed
    # by the same independent read used above.
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    assert described.get("NetworkServices", []) == [], described

    # The filter this check created is proved gone, not merely handed to on_cleanup
    # unasserted, and the operation under test is proved unusable against the dead id.
    del_resp = ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id)
    assert del_resp["TrafficMirrorFilterId"] == filter_id, del_resp

    code, code_msg = _client_error(
        lambda: ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])
    )
    assert code == "InvalidTrafficMirrorFilterId.NotFound", f"expected NotFound, got {code!r}"
    assert code_msg == f"{filter_id} does not exist", code_msg

    code, code_msg = _client_error(
        lambda: ec2.modify_traffic_mirror_filter_network_services(
            TrafficMirrorFilterId=filter_id, AddNetworkServices=["amazon-dns"]
        )
    )
    assert code == "InvalidTrafficMirrorFilterId.NotFound", f"expected NotFound, got {code!r}"
    assert code_msg == f"{filter_id} does not exist", code_msg


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTrafficMirrorFilterId.NotFound":
            raise


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
