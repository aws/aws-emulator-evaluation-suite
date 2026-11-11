"""create-connection-with-nonexistent-host-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-connection-with-nonexistent-host-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call SUCCEEDED and returned {result!r}")


def _all_connection_arns(ctx, cc) -> set:
    arns: set = set()
    token = None
    for _ in range(20):  # bounded pagination, generous for a test account
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_connections(**kwargs)
        arns.update(c["ConnectionArn"] for c in page.get("Connections", []))
        token = page.get("NextToken")
        if not token:
            break
    return arns


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnection with the HostArn of a nonexistent host raises ResourceNotFoundException and
    creates no connection, while CreateConnection without a HostArn creates a PENDING one."""
    cc = ctx.client("codeconnections")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_host_arn = f"arn:aws:codeconnections:{ctx.region}:{account_id}:host/{uuid.uuid4()}"

    before = _all_connection_arns(ctx, cc)

    code, message = _error_code(
        lambda: cc.create_connection(
            ConnectionName=ctx.unique_name("s2rcc-")[-32:], HostArn=fake_host_arn
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No host exists with the ARN: {fake_host_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _all_connection_arns(ctx, cc)
    assert after == before, "a connection was created despite the invalid HostArn"

    # positive control: CreateConnection without a HostArn still succeeds
    name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))
    status = cc.get_connection(ConnectionArn=conn_arn)["Connection"]["ConnectionStatus"]
    assert status == "PENDING", f"expected PENDING, got {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
