"""get-host-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-host-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHost on an ARN that was never created returns ResourceNotFoundException,
    while GetHost on a real host succeeds -- a positive control proving the negative
    is specific to the fabricated ARN and not just GetHost failing outright."""
    cc = ctx.client("codeconnections")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-host-")[:64]
    endpoint = "https://ghe.example.com"
    real_arn = cc.create_host(
        Name=name, ProviderType="GitHubEnterpriseServer", ProviderEndpoint=endpoint
    )["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=real_arn))

    # positive control: GetHost is otherwise functional on the same wiring
    real = cc.get_host(HostArn=real_arn)
    assert real["Name"] == name, f"expected Name {name!r}, got {real.get('Name')!r}"

    fake_arn = f"arn:aws:codeconnections:{ctx.region}:{account_id}:host/{uuid.uuid4()}"
    code, message = _error(lambda: cc.get_host(HostArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code!r}"
    )
    expected = f"No host exists with the ARN: {fake_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
