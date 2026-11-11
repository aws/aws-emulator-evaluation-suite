"""delete-host-removes-from-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-host-removes-from-list"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all_host_arns(csc) -> list[str]:
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = csc.list_hosts(**kwargs)
        arns.extend(h["HostArn"] for h in resp.get("Hosts", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteHost (with no attached connections) removes the host permanently and it becomes
    unusable: an independent list no longer reflects it, a get returns not-found, and a mutation
    against the dead ARN is also rejected rather than silently accepted.
    """
    csc = ctx.client("codestar-connections")
    arn = csc.create_host(
        Name=ctx.unique_name("sim2real-behav-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghes.example.net",
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(csc, arn))

    arns_before = _list_all_host_arns(csc)
    assert arn in arns_before, f"expected {arn} in list_hosts before delete, got {arns_before}"

    csc.delete_host(HostArn=arn)

    arns_after = _list_all_host_arns(csc)
    assert arn not in arns_after, f"expected {arn} absent from list_hosts after delete, got {arns_after}"

    expected_message = f"No host exists with the ARN: {arn}"
    err = _error(lambda: csc.get_host(HostArn=arn))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException from get_host on deleted host, got {err}"
    assert err["Message"] == expected_message, err["Message"]

    err2 = _error(lambda: csc.update_host(HostArn=arn, ProviderEndpoint="https://ghes-after-delete.example.net"))
    assert err2["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException from update_host on deleted host, got {err2}"
    assert err2["Message"] == expected_message, err2["Message"]


def _safe_delete_host(csc, arn: str) -> None:
    try:
        csc.delete_host(HostArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
