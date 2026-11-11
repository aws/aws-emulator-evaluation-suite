"""host-delete-removes-and-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteHost permanently removes the host: it disappears from GetHost
    (ResourceNotFoundException) and from ListHosts, and a further mutation
    against the dead ARN (UpdateHost) is also rejected as not-found."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-host-")[:64]
    arn = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
    )["HostArn"]
    ctx.on_cleanup(lambda: _delete_host_if_present(cc, arn))

    status = cc.get_host(HostArn=arn)["Status"]
    assert status == "PENDING", f"expected freshly created host to be PENDING, got {status!r}"

    cc.delete_host(HostArn=arn)

    expected_message = f"No host exists with the ARN: {arn}"
    code, message = _error(lambda: cc.get_host(HostArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetHost on a deleted host to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, f"GetHost message: {message!r}"

    arns_after = {h["HostArn"] for h in _iter_hosts(cc)}
    assert arn not in arns_after, f"deleted host {arn} still present in ListHosts"

    update_code, update_message = _error(
        lambda: cc.update_host(HostArn=arn, ProviderEndpoint="https://ghe-updated.example.com")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateHost on a deleted host to raise ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == expected_message, f"UpdateHost message: {update_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_host_if_present(cc, arn):
    from botocore.exceptions import ClientError

    try:
        cc.delete_host(HostArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _iter_hosts(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_hosts(**kwargs)
        yield from resp.get("Hosts", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
