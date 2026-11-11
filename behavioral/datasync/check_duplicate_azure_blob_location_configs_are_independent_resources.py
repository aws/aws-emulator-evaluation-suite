"""duplicate-azure-blob-location-configs-are-independent-resources."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-azure-blob-location-configs-are-independent-resources"
GROUP = "representation"
SERVICES = ["datasync"]


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateLocationAzureBlob does not dedupe: two calls with an identical container, path and
    SAS token mint two distinct locations, and deleting one leaves the other untouched.
    """
    ds = ctx.client("datasync")
    container = ctx.unique_name("sim2real-behav-dsazure-")
    container_url = f"https://{container}.blob.core.windows.net/sim2real"
    sas = {"Token": "sv=2020-08-04&ss=b&srt=co&sp=rwdlacx&se=2099-01-01T00%3A00%3A00Z&sig=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ%3D"}

    first = ds.create_location_azure_blob(
        ContainerUrl=container_url, AuthenticationType="SAS", SasConfiguration=sas,
        Tags=[{"Key": "sim2real", "Value": container}],
    )["LocationArn"]
    ctx.on_cleanup(_teardown(lambda: ds.delete_location(LocationArn=first), "InvalidRequestException"))

    second = ds.create_location_azure_blob(
        ContainerUrl=container_url, AuthenticationType="SAS", SasConfiguration=sas,
        Tags=[{"Key": "sim2real", "Value": container}],
    )["LocationArn"]
    ctx.on_cleanup(_teardown(lambda: ds.delete_location(LocationArn=second), "InvalidRequestException"))

    assert first != second, (
        f"two CreateLocationAzureBlob calls with the identical config minted the same ARN {first!r}"
    )

    before = _list_by_prefix(ctx, f"azure-blob://{container}.blob.core.windows.net/")
    assert before == {first, second}, (
        f"ListLocations for this check's container returned {sorted(before)}, expected both {first!r} and {second!r}"
    )

    ds.delete_location(LocationArn=first)

    code, message = _error(lambda: ds.describe_location_azure_blob(LocationArn=first))
    assert code == "InvalidRequestException", (
        f"describing the deleted location gave {code!r}, expected 'InvalidRequestException'"
    )
    expected_message = f"Location {first} is not found."
    assert message == expected_message, (
        f"describing the deleted location said {message!r}, expected {expected_message!r}"
    )

    still_there = ds.describe_location_azure_blob(LocationArn=second)
    assert still_there["LocationArn"] == second, (
        f"the location this check did not delete now describes as {still_there['LocationArn']!r}, expected {second!r}"
    )

    after = _list_by_prefix(ctx, f"azure-blob://{container}.blob.core.windows.net/")
    assert after == {second}, (
        f"after deleting one of the two locations, the listing is {sorted(after)}, expected only {second!r}"
    )



def _error(fn) -> tuple:
    """Return the (code, message) of the AWS error ``fn`` raises; raise if the call succeeds."""
    try:
        fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        code = error.get("Code")
        if code is None:
            raise AssertionError(f"exception carried no AWS error code: {exc!r}") from exc
        return code, error.get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code to read")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone.
    """

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _list_by_prefix(ctx, uri_prefix: str) -> set:
    ds = ctx.client("datasync")
    out = set()
    for page in ds.get_paginator("list_locations").paginate(
        Filters=[{"Name": "LocationUri", "Operator": "BeginsWith", "Values": [uri_prefix]}]
    ):
        out.update(loc["LocationArn"] for loc in page.get("Locations", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
