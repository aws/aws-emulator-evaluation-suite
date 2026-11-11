"""ip-route-nonexistent-directory-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ip-route-nonexistent-directory-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes, ListIpRoutes and RemoveIpRoutes on a well-formed nonexistent DirectoryId each fail with
    EntityDoesNotExistException and "Directory: '<id>' does not exist.", while DescribeDirectories still
    answers, so no route state is fabricated for a directory that was never created."""
    ds = ctx.client("ds")
    bogus_directory_id = "d-9999999999"

    not_found = f"Directory: '{bogus_directory_id}' does not exist."

    add_code, add_message, add_request = _client_error(
        lambda: ds.add_ip_routes(
            DirectoryId=bogus_directory_id,
            IpRoutes=[{"CidrIp": "203.0.113.0/24", "Description": "sim2real nonexistent"}],
        )
    )
    assert add_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException from AddIpRoutes for a nonexistent "
        f"DirectoryId, got {add_code!r}"
    )
    expected = f"{not_found} : RequestId: {add_request}"
    assert add_message == expected, f"AddIpRoutes must refuse with {expected!r}, got {add_message!r}"

    list_code, list_message, list_request = _client_error(
        lambda: ds.list_ip_routes(DirectoryId=bogus_directory_id)
    )
    assert list_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException from ListIpRoutes for a nonexistent "
        f"DirectoryId, got {list_code!r}"
    )
    expected = f"{not_found} : RequestId: {list_request}"
    assert list_message == expected, (
        f"ListIpRoutes must refuse with {expected!r}, got {list_message!r}"
    )

    remove_code, remove_message, remove_request = _client_error(
        lambda: ds.remove_ip_routes(DirectoryId=bogus_directory_id, CidrIps=["203.0.113.0/24"])
    )
    assert remove_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException from RemoveIpRoutes for a nonexistent "
        f"DirectoryId, got {remove_code!r}"
    )
    expected = f"{not_found} : RequestId: {remove_request}"
    assert remove_message == expected, (
        f"RemoveIpRoutes must refuse with {expected!r}, got {remove_message!r}"
    )

    # Control: the account-scoped read path is healthy, so the three rejections above are
    # about the bogus DirectoryId and not a broken client, region or credential.
    assert isinstance(
        ds.describe_directories().get("DirectoryDescriptions"), list
    ), "DescribeDirectories must still succeed after the refused IP route operations"


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
