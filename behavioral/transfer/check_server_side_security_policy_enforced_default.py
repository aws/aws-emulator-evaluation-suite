"""server-side-security-policy-enforced-default."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-security-policy-enforced-default"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A server created without SecurityPolicyName gets a default SERVER policy covering SFTP,
    resolvable via DescribeSecurityPolicy; after deletion DescribeServer is ResourceNotFound."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]

    def _cleanup():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    described = transfer.describe_server(ServerId=server_id)["Server"]
    policy_name = described.get("SecurityPolicyName")
    assert policy_name, "expected a server-side default SecurityPolicyName to be assigned"
    assert policy_name.startswith("Transfer"), f"unexpected default security policy name {policy_name!r}"

    policy = transfer.describe_security_policy(SecurityPolicyName=policy_name)["SecurityPolicy"]
    assert policy["SecurityPolicyName"] == policy_name, (
        f"DescribeSecurityPolicy({policy_name!r}) echoed {policy.get('SecurityPolicyName')!r}"
    )
    assert policy["Type"] == "SERVER", f"expected a SERVER-scoped security policy, got {policy['Type']!r}"
    assert "SFTP" in policy.get("Protocols", []), (
        f"expected the default server security policy to cover SFTP, got {policy.get('Protocols')!r}"
    )

    transfer.delete_server(ServerId=server_id)
    code, message = _err(lambda: transfer.describe_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", f"expected 404 after delete, got {code}"
    assert message == "Unknown server", f"unexpected message after delete {message!r}"


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
