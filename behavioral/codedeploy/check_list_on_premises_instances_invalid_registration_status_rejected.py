"""list-on-premises-instances-invalid-registration-status-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-on-premises-instances-invalid-registration-status-rejected"
GROUP = "negative-classes"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOnPremisesInstances with a registrationStatus value outside the
    Registered/Deregistered enum must fail with InvalidRegistrationStatusException."""
    cd = ctx.client("codedeploy")

    code, message = _error(
        lambda: cd.list_on_premises_instances(registrationStatus="NotARealStatus")
    )
    assert code == "InvalidRegistrationStatusException", (
        f"expected InvalidRegistrationStatusException for an out-of-enum registrationStatus, got {code!r}"
    )
    assert message == "Registration status NotARealStatus is not valid.", message

    # positive control: a valid enum value is accepted and returns a well-formed page
    resp = cd.list_on_premises_instances(registrationStatus="Registered")
    assert "instanceNames" in resp, f"expected instanceNames key in response, got {resp!r}"
    assert isinstance(resp["instanceNames"], list), (
        f"expected instanceNames to be a list, got {type(resp['instanceNames'])!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING an out-of-enum value real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects registrationStatus='NotARealStatus', but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
