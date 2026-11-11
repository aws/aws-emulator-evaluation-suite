"""usage-profile-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-profile-configuration-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The Configuration map supplied on CreateUsageProfile is returned unchanged by
    GetUsageProfile, and DeleteUsageProfile removes it (a subsequent Get raises
    EntityNotFoundException)."""
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-usageprofile-")
    # Configuration parameter keys are fixed, lower-camel-case names defined by the Glue usage
    # profile schema (see the AWS Glue admin guide's create-usage-profile example) -- arbitrary
    # keys are silently dropped rather than round-tripped, so this uses the real key set.
    # CreateUsageProfile also requires that whenever a SessionConfiguration/JobConfiguration
    # block is present, both workerType and numberOfWorkers carry a DefaultValue together
    # ("Please set default value for both Worker type and Number of workers") -- setting only
    # one of the pair is rejected with InvalidInputException.
    configuration = {
        "SessionConfiguration": {
            "workerType": {
                "DefaultValue": "G.1X",
                "AllowedValues": ["G.1X", "G.2X"],
            },
            "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
            "idleTimeout": {"DefaultValue": "30", "MinValue": "5", "MaxValue": "120"},
        },
        "JobConfiguration": {
            "workerType": {
                "DefaultValue": "G.1X",
                "AllowedValues": ["G.1X", "G.2X"],
            },
            "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
        },
    }

    glue.create_usage_profile(
        Name=name,
        Description="sim2real fidelity check profile",
        Configuration=configuration,
        Tags={"sim2real": CHECK},
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            glue.delete_usage_profile(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    fetched = glue.get_usage_profile(Name=name)
    assert fetched["Name"] == name, f"expected Name {name!r}, got {fetched.get('Name')!r}"
    assert fetched["Configuration"] == configuration, (
        f"Configuration did not round-trip: sent {configuration!r}, got {fetched['Configuration']!r}"
    )

    glue.delete_usage_profile(Name=name)
    code, message = _error(lambda: glue.get_usage_profile(Name=name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after delete, got {code!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
