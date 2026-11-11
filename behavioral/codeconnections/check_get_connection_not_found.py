"""get-connection-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-connection-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnection on a well-formed ARN derived from a real connection's ARN raises
    ResourceNotFoundException, while the real ARN reads back."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    real_arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=real_arn))

    positive = cc.get_connection(ConnectionArn=real_arn)["Connection"]
    assert positive["ConnectionArn"] == real_arn, (
        f"positive control: GetConnection on the just-created connection returned "
        f"{positive['ConnectionArn']!r}, expected {real_arn!r}"
    )

    bogus_arn = real_arn.rsplit("/", 1)[0] + f"/{uuid.uuid4()}"
    code, message = _error_code(lambda: cc.get_connection(ConnectionArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"GetConnection on a never-created connection ARN returned code {code!r}, expected "
        f"'ResourceNotFoundException'"
    )
    expected = "No connection exists with the ARN"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
