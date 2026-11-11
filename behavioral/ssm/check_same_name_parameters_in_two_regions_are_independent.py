"""same-name-parameters-in-two-regions-are-independent."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "same-name-parameters-in-two-regions-are-independent"
GROUP = "cross-region"
SERVICES = ["ssm"]

_NOT_FOUND = ("ParameterNotFound", "")


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


def _delete_parameter(ssm, name: str) -> None:
    """Delete the parameter; tolerates only not-found."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A parameter name is scoped to its region: absent in a second region until created there.

    Then two parameters keep their own values, versions and ARNs; deleting one keeps the other.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html
    """
    home, away = ctx.region, _other_region(ctx.region)
    ssm = ctx.client("ssm")
    ssm_away = ctx.client("ssm", region=away)
    name = "/" + ctx.unique_name("sim2real-behav-xr-param-")
    ctx.on_cleanup(lambda: _delete_parameter(ssm, name))
    ctx.on_cleanup(lambda: _delete_parameter(ssm_away, name))

    ssm.put_parameter(Name=name, Value="home-v1", Type="String")
    assert ssm.get_parameter(Name=name)["Parameter"]["Value"] == "home-v1"
    assert _error(lambda: ssm_away.get_parameter(Name=name)) == _NOT_FOUND, (
        f"a parameter created in {home} must not be readable in {away}"
    )

    ssm_away.put_parameter(Name=name, Value="away-v1", Type="String")
    put = ssm.put_parameter(Name=name, Value="home-v2", Type="String", Overwrite=True)
    assert put["Version"] == 2, f"the overwrite in {home} answered {put!r}"
    got_home = ssm.get_parameter(Name=name)["Parameter"]
    got_away = ssm_away.get_parameter(Name=name)["Parameter"]
    assert (got_home["Value"], got_home["Version"]) == ("home-v2", 2), (
        f"home parameter {got_home!r}"
    )
    assert (got_away["Value"], got_away["Version"]) == ("away-v1", 1), (
        f"the {away} parameter must keep its own value and version; got {got_away!r}"
    )
    ha, aa = got_home["ARN"].split(":"), got_away["ARN"].split(":")
    assert (ha[3], aa[3]) == (home, away), f"ARN regions {ha[3]!r} and {aa[3]!r}"
    assert ha[:3] + ha[4:] == aa[:3] + aa[4:], "the two ARNs must differ only in the region field"

    ssm_away.delete_parameter(Name=name)
    assert _error(lambda: ssm_away.get_parameter(Name=name)) == _NOT_FOUND
    assert ssm.get_parameter(Name=name)["Parameter"]["Value"] == "home-v2", (
        f"deleting the {away} parameter must leave the {home} one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
