"""connection-arn-never-reused-after-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-arn-never-reused-after-delete"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A connection recreated with a deleted connection's name gets a different ARN, and the deleted ARN
    raises ResourceNotFoundException (the documented never-reused ARN)."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    owner_tag = [{"Key": "owner", "Value": "sim2real"}]

    arn_1 = cc.create_connection(ConnectionName=name, ProviderType="GitHub", Tags=owner_tag)["ConnectionArn"]
    cc.delete_connection(ConnectionArn=arn_1)

    arn_2 = cc.create_connection(ConnectionName=name, ProviderType="GitHub", Tags=owner_tag)["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn_2))

    assert arn_2 != arn_1, (
        f"expected a fresh ConnectionArn for reused name {name!r}, got the deleted ARN {arn_1!r} again"
    )
    got = cc.get_connection(ConnectionArn=arn_2)["Connection"]
    assert got["ConnectionName"] == name, (
        f"expected ConnectionName {name!r} on {arn_2!r}, got {got['ConnectionName']!r}"
    )

    code, message = _error(lambda: cc.get_connection(ConnectionArn=arn_1))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted {arn_1!r}, got {code!r}"
    )
    expected = "No connection exists with the ARN"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: cc.tag_resource(ResourceArn=arn_1, Tags=[{"Key": "probe", "Value": "dead"}]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging deleted {arn_1!r}, got {code!r}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
