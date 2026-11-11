"""role-session-duration-and-description-bounds-rejected."""
from __future__ import annotations

import json

from botocore.config import Config
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "role-session-duration-and-description-bounds-rejected"
GROUP = 'errors'
SERVICES = ['iam']

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# Contract limits from the service model, not adjustable account quotas:
#   roleMaxSessionDurationType : integer, range 3600..43200
#   roleDescriptionType        : string,  length 0..1000
MIN_SESSION = 3600
MAX_SESSION = 43200
DEFAULT_SESSION = 3600      # documented default when MaxSessionDuration is omitted
MAX_DESCRIPTION = 1000

# IAM refuses every out-of-range value server-side with ValidationError and a message naming the
# member and the violated constraint. The whole message is asserted because "ValidationError" alone
# is IAM's answer to many unrelated conditions.
MSG_UNDER_MIN = (
    "1 validation error detected: Value at 'maxSessionDuration' failed to satisfy constraint: "
    "Member must have value greater than or equal to 3600"
)
MSG_OVER_MAX = (
    "1 validation error detected: Value at 'maxSessionDuration' failed to satisfy constraint: "
    "Member must have value less than or equal to 43200"
)
MSG_DESC_TOO_LONG = (
    "1 validation error detected: Value at 'description' failed to satisfy constraint: "
    "Member must have length less than or equal to 1000"
)


def _err(fn):
    """Call fn(); return (Code, Message) of the ClientError. A successful call raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call succeeded where AWS refuses it and returned {result!r}")


def _unvalidated_client(ctx):
    """An IAM client with client-side parameter validation off: botocore enforces the model's
    MaxSessionDuration range locally, so only an unvalidated request reaches the service."""
    return ctx.client(
        "iam", config=Config(retries={"max_attempts": 1}, parameter_validation=False)
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaxSessionDuration defaults to 3600, accepts 3600 and 43200, and rejects 3599, 43201 and 0
    (and 43201 on CreateRole) with exact ValidationError messages, leaving stored state unchanged;
    Description accepts 1000 characters and rejects 1001.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateRole.html
    """
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")

    # --- Omitted MaxSessionDuration must default to 3600 as OBSERVED BY GetRole and ListRoles.
    # MaxSessionDuration is an optional member of CreateRole's Role, so whether the create
    # response carries it is not graded here.
    created = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/sim2real-behav/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    assert created["Tags"] == [{"Key": "sim2real", "Value": CHECK}], (
        f"CreateRole must echo back the Tags it was given verbatim, got {created['Tags']!r}"
    )

    def _stored():
        got = iam.get_role(RoleName=role)["Role"]
        return got["MaxSessionDuration"], got.get("Description")

    read_duration, _ = _stored()
    assert read_duration == DEFAULT_SESSION, (
        "a role created without MaxSessionDuration must read back as the documented "
        f"{DEFAULT_SESSION}s from GetRole, got {read_duration!r}"
    )
    listed = [
        r for page in iam.get_paginator("list_roles").paginate(PathPrefix="/sim2real-behav/")
        for r in page["Roles"] if r["RoleName"] == role
    ]
    assert len(listed) == 1, f"the new role must appear exactly once in ListRoles, got {listed!r}"
    assert listed[0].get("MaxSessionDuration") == DEFAULT_SESSION, (
        f"ListRoles materialises the same default as GetRole, got "
        f"{listed[0].get('MaxSessionDuration')!r}"
    )

    # --- Accepted: exactly the minimum, then exactly the maximum.
    for legal in (MIN_SESSION, MAX_SESSION):
        iam.update_role(RoleName=role, MaxSessionDuration=legal)
        duration, _ = _stored()
        assert duration == legal, (
            f"MaxSessionDuration={legal} is the documented boundary and must be accepted and "
            f"echoed by GetRole, got {duration!r}"
        )

    # The role now sits at MAX_SESSION; every rejection below must leave it there.
    baseline_duration, _ = _stored()
    assert baseline_duration == MAX_SESSION, (
        f"role must sit at the MAX_SESSION boundary ({MAX_SESSION}) after the loop above accepted "
        f"it, got {baseline_duration!r}"
    )

    # --- Rejected: one second under the minimum, one second over the maximum, and zero.
    #
    # These go through the unvalidated client so the request actually reaches the service; see
    # _unvalidated_client for why. Each message is asserted, and the under- and over-bound
    # messages differ, so one catch-all range error fails here.
    raw = _unvalidated_client(ctx)
    for illegal, expected_msg in (
        (MIN_SESSION - 1, MSG_UNDER_MIN),
        (MAX_SESSION + 1, MSG_OVER_MAX),
        (0, MSG_UNDER_MIN),
    ):
        code, msg = _err(lambda v=illegal: raw.update_role(RoleName=role, MaxSessionDuration=v))
        assert code == "ValidationError", (
            f"MaxSessionDuration={illegal} is outside the documented {MIN_SESSION}..{MAX_SESSION} "
            f"range and must be ValidationError, got {code!r}"
        )
        assert msg == expected_msg, (
            f"the refusal of MaxSessionDuration={illegal} must name the member and the bound it "
            f"violated ({expected_msg!r}); got {msg!r}"
        )
        duration, _ = _stored()
        assert duration == baseline_duration, (
            f"the rejected UpdateRole(MaxSessionDuration={illegal}) must not mutate the role; "
            f"stored value went from {baseline_duration} to {duration}"
        )

    # --- The same bound is enforced on CreateRole, not just UpdateRole.
    over_role = ctx.unique_name("sim2real-behav-role-over-")
    code, msg = _err(
        lambda: raw.create_role(
            RoleName=over_role,
            AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
            MaxSessionDuration=MAX_SESSION + 1,
        )
    )
    assert code == "ValidationError", (
        f"CreateRole with MaxSessionDuration={MAX_SESSION + 1} must be ValidationError, got {code!r}"
    )
    assert msg == MSG_OVER_MAX, (
        f"CreateRole must refuse the over-range duration with the same member-and-bound message as "
        f"UpdateRole ({MSG_OVER_MAX!r}); got {msg!r}"
    )
    gone = ("NoSuchEntity", f"The role with name {over_role} cannot be found.")
    assert _err(lambda: iam.get_role(RoleName=over_role)) == gone, (
        f"the rejected CreateRole must not have created {over_role!r}"
    )

    # --- Accepted: a Description at exactly the maximum length.
    max_desc = "d" * MAX_DESCRIPTION
    iam.update_role(RoleName=role, Description=max_desc)
    duration, description = _stored()
    assert description == max_desc, (
        f"a {MAX_DESCRIPTION}-character Description is legal and must round-trip verbatim; got "
        f"length {len(description or '')}"
    )

    # --- Rejected: one character over. The stored description must survive intact.
    #
    # Unlike the numeric range, roleDescriptionType's length bound is NOT enforced
    # client-side by botocore, so the ordinary harness client is enough to reach the service here.
    code, msg = _err(
        lambda: iam.update_role(RoleName=role, Description="d" * (MAX_DESCRIPTION + 1))
    )
    assert code == "ValidationError", (
        f"a {MAX_DESCRIPTION + 1}-character Description exceeds roleDescriptionType and must be "
        f"ValidationError, got {code!r}"
    )
    assert msg == MSG_DESC_TOO_LONG, (
        f"the refusal must name 'description' and its length bound ({MSG_DESC_TOO_LONG!r}), which "
        f"is what distinguishes it from the duration refusals above; got {msg!r}"
    )
    duration_after, description_after = _stored()
    assert description_after == max_desc, (
        "the rejected UpdateRole must leave the previous Description in place; got length "
        f"{len(description_after or '')}"
    )
    assert duration_after == baseline_duration, (
        "the rejected Description update must not have touched MaxSessionDuration either; got "
        f"{duration_after!r}"
    )

    # --- Control: a legal update of BOTH fields still lands after all the rejections.
    iam.update_role(RoleName=role, MaxSessionDuration=7200, Description="sim2real-behav ok")
    duration_final, description_final = _stored()
    assert (duration_final, description_final) == (7200, "sim2real-behav ok"), (
        "a legal UpdateRole must still be applied after the rejection legs, got "
        f"{(duration_final, description_final)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
