"""usage-profile-lifecycle-create-get-delete-404."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-profile-lifecycle-create-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsageProfile persists the profile, GetUsageProfile returns it, DeleteUsageProfile
    removes it and a subsequent GetUsageProfile raises EntityNotFoundException."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-usageprofile-")

    glue.create_usage_profile(
        Name=name,
        Description="behavioral fidelity check",
        Configuration={
            "SessionConfiguration": {
                "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "5"},
                "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            },
            "JobConfiguration": {
                "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "5"},
                "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            },
        },
        Tags={"sim2real": CHECK},
    )

    ctx.on_cleanup(lambda: _cleanup_usage_profile(glue, name))

    got = glue.get_usage_profile(Name=name)
    assert got["Name"] == name, f"GetUsageProfile returned Name={got['Name']!r}, expected {name!r}"
    assert got["Description"] == "behavioral fidelity check", (
        f"GetUsageProfile returned Description={got['Description']!r}, expected "
        f"'behavioral fidelity check'"
    )
    session_default = got["Configuration"]["SessionConfiguration"]["numberOfWorkers"]["DefaultValue"]
    assert session_default == "2", (
        f"GetUsageProfile returned SessionConfiguration.numberOfWorkers.DefaultValue="
        f"{session_default!r}, expected '2'"
    )

    glue.delete_usage_profile(Name=name)

    code, message = _error(lambda: glue.get_usage_profile(Name=name))
    assert code == "EntityNotFoundException", (
        f"GetUsageProfile after delete returned code={code!r}, expected 'EntityNotFoundException'"
    )
    expected = f"UsageProfile {name} does not exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cleanup_usage_profile(glue, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_usage_profile(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
