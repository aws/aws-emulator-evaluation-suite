"""put-auth-policy-malformed-json-rejected-existing-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-auth-policy-malformed-json-rejected-existing-unchanged"
GROUP = 'auth-policy-rejection'
SERVICES = ['vpc-lattice']


def _error(fn):
    """The AWS (code, message) ``fn()`` raised; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A malformed PutAuthPolicy document is refused and leaves the existing policy untouched,
    while a well-formed replacement on the same resource still succeeds afterwards.
    """
    vl = ctx.client("vpc-lattice")

    net = vl.create_service_network(
        name=ctx.unique_name("sim2real-latt-bapm-"), authType="AWS_IAM",
        tags={"sim2real": "vpc-lattice-auth-policy-rejection"},
    )
    ctx.on_cleanup(lambda i=net["id"]: vl.delete_service_network(serviceNetworkIdentifier=i))

    original = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
        '"Action":"vpc-lattice-svcs:Invoke","Resource":"*"}]}'
    )
    vl.put_auth_policy(resourceIdentifier=net["id"], policy=original)
    ctx.on_cleanup(lambda i=net["id"]: vl.delete_auth_policy(resourceIdentifier=i))

    error = _error(lambda: vl.put_auth_policy(resourceIdentifier=net["id"], policy="{not valid json"))
    assert error == ("ValidationException", "Not a valid policy"), (
        f"PutAuthPolicy with malformed JSON raised {error!r}, expected "
        f"('ValidationException', 'Not a valid policy')"
    )

    unchanged = vl.get_auth_policy(resourceIdentifier=net["id"])
    assert unchanged["policy"] == original, (
        f"after the refused Put, GetAuthPolicy reports {unchanged['policy']!r}; the prior policy "
        f"{original!r} must survive a rejected replacement untouched"
    )
    assert unchanged["state"] == "Active", (
        f"the network is AWS_IAM, so the surviving policy must still read state Active, got "
        f"{unchanged['state']!r}"
    )

    replacement = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
        '"Action":"vpc-lattice-svcs:Invoke","Resource":"*",'
        '"Condition":{"StringEquals":{"aws:PrincipalType":"AWS"}}}]}'
    )
    put = vl.put_auth_policy(resourceIdentifier=net["id"], policy=replacement)
    assert put["policy"] == replacement, (
        f"a well-formed replacement after the refusal returned {put['policy']!r}; the resource "
        f"must still accept good input (positive control)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
