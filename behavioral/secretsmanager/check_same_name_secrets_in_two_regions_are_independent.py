"""same-name-secrets-in-two-regions-are-independent."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "same-name-secrets-in-two-regions-are-independent"
GROUP = "cross-region"
SERVICES = ["secretsmanager"]

_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _other_region(region: str) -> str:
    """A second commercial region of the same account."""
    # Region-pinned by design: two commercial regions every account has enabled.
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_secret(sm, name: str) -> None:
    """Delete the secret without recovery; tolerates only not-found."""
    try:
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A secret name is scoped to its region: absent in a second region until created there.

    Then two unreplicated secrets keep their own values and ARNs; a write to one leaves the other.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html
    """
    home, away = ctx.region, _other_region(ctx.region)
    sm = ctx.client("secretsmanager")
    sm_away = ctx.client("secretsmanager", region=away)
    name = ctx.unique_name("sim2real-behav-xr-secret-")
    ctx.on_cleanup(lambda: _delete_secret(sm, name))
    ctx.on_cleanup(lambda: _delete_secret(sm_away, name))

    home_arn = sm.create_secret(Name=name, SecretString="home-v1")["ARN"]
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "home-v1"
    assert _error(lambda: sm_away.get_secret_value(SecretId=name)) == _NOT_FOUND, (
        f"a secret created in {home} must not be readable in {away}"
    )

    away_arn = sm_away.create_secret(Name=name, SecretString="away-v1")["ARN"]
    assert (home_arn.split(":")[3], away_arn.split(":")[3]) == (home, away), (
        f"ARN regions of {home_arn!r} and {away_arn!r}"
    )
    sm.put_secret_value(SecretId=name, SecretString="home-v2")
    got = (
        sm.get_secret_value(SecretId=name)["SecretString"],
        sm_away.get_secret_value(SecretId=name)["SecretString"],
    )
    assert got == ("home-v2", "away-v1"), f"each region must keep its own value; got {got!r}"
    described = sm_away.describe_secret(SecretId=name)
    assert (described["ARN"], "ReplicationStatus" in described) == (away_arn, False), (
        f"the {away} secret must be its own unreplicated secret; DescribeSecret {described!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
