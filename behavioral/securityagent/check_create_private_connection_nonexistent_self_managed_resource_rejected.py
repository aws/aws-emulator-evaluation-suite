"""create-private-connection-nonexistent-self-managed-resource-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-private-connection-nonexistent-self-managed-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["securityagent"]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A self-managed private connection naming a nonexistent resourceConfigurationId is refused with
    ResourceNotFoundException and its exact message, is never persisted (not listed; describing it
    answers "Private Connection not found: null"), and a create/delete round trip still works."""
    sa = ctx.client("securityagent")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-privconn-")
    account_id = sts.get_caller_identity()["Account"]
    fake_rcfg_arn = (
        f"arn:aws:vpc-lattice:{ctx.region}:{account_id}:resourceconfiguration/"
        f"rcfg-{uuid.uuid4().hex[:17]}"
    )

    code, message = _error(
        lambda: sa.create_private_connection(
            privateConnectionName=name,
            mode={"selfManaged": {"resourceConfigurationId": fake_rcfg_arn}},
        )
    )
    assert code == "ResourceNotFoundException", f"unexpected code {code!r}"
    expected = (
        f"A resource referenced by private connection '{name}' was not found. "
        "Verify the resource configuration exists and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the connection was never persisted
    matches = [c for c in sa.list_private_connections()["privateConnections"] if c["name"] == name]
    assert matches == [], f"expected no private connection named {name!r}, found {matches!r}"
    describe_code, describe_message = _error(lambda: sa.describe_private_connection(privateConnectionName=name))
    assert describe_code == "ResourceNotFoundException", f"unexpected code {describe_code!r}"
    # AWS renders the missing connection as the literal "null", not the requested name
    assert describe_message == "Private Connection not found: null", (
        f"expected message 'Private Connection not found: null', got {describe_message!r}"
    )

    # positive control: account/API is generally functional (create+delete round trip)
    pack_id = sa.create_security_requirement_pack(name=ctx.unique_name("sim2real-behav-pack-"))["packId"]

    def _cleanup_pack():
        try:
            sa.delete_security_requirement_pack(packId=pack_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_pack)
    sa.delete_security_requirement_pack(packId=pack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

