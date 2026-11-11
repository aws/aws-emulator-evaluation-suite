"""entity-name-length-and-charset-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "entity-name-length-and-charset-rejected"
GROUP = 'errors'
SERVICES = ['iam']

ALLOW_S3_LIST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)

# Fixed name/path length and character limits from the IAM Smithy model (shape constraints,
# NOT adjustable account quotas).
MAX_USER_NAME = 64          # userNameType  length 1..64,  pattern ^[\w+=,.@-]+$
MAX_GROUP_NAME = 128        # groupNameType length 1..128, pattern ^[\w+=,.@-]+$
MAX_POLICY_NAME = 128       # policyNameType length 1..128
MAX_PATH = 512              # pathType      length 1..512, must start and end with '/'
BAD_NAME_CHARS = "/#!"      # outside the ^[\w+=,.@-]+$ character class

# The two halves of userNameType are enforced at DIFFERENT layers on real IAM and produce
# different refusals, which is what the read-path pair below asserts:
#   CreateUser, 65 chars   -> ValidationError (length constraint)
#   GetUser,    65 chars   -> NoSuchEntity    (the lookup misses)
#   GetUser,    '/' in name-> ValidationError (character class)
MSG_BAD_CHARSET = (
    "The specified value for userName is invalid. It must contain only alphanumeric characters "
    "and/or the following: +=,.@_-"
)
MSG_BAD_PATH = (
    "The specified value for path is invalid. It must begin and end with / and contain only "
    "alphanumeric characters and/or / characters."
)


def _err(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises, so a target that
    accepts a name real IAM refuses cannot read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _refused_exactly(fn, code, message, what):
    """fn() is refused with exactly ``code`` and exactly ``message``."""
    got_code, got_message = _err(fn)
    assert got_code == code, f"{what}: expected {code}, got {got_code!r}"
    assert got_message == message, f"{what}: expected message {message!r}, got {got_message!r}"


def _pad(base, target_len, filler="x"):
    """`base` extended with `filler` to exactly target_len chars (base must be shorter)."""
    assert len(base) < target_len, f"base {base!r} already exceeds {target_len}"
    return base + filler * (target_len - len(base))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IAM accepts user, group, policy names and paths at their maximum length and rejects one character more,
    a character outside ^[\\w+=,.@-]+$ or a path missing a slash with the exact ValidationError, creating
    nothing; GetUser rejects a bad character the same way but answers NoSuchEntity for 65 characters."""
    iam = ctx.client("iam")
    base_user = ctx.unique_name("sim2real-behav-u-")
    base_group = ctx.unique_name("sim2real-behav-g-")
    base_policy = ctx.unique_name("sim2real-behav-p-")

    # ---------- accepted: exactly at the documented maximum ----------
    max_user = _pad(base_user, MAX_USER_NAME)
    assert len(max_user) == MAX_USER_NAME, f"test setup bug: padded name is {len(max_user)} chars, want {MAX_USER_NAME}"
    created = iam.create_user(UserName=max_user)["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=max_user))
    assert created["UserName"] == max_user, (
        f"a {MAX_USER_NAME}-character user name is legal and must round-trip verbatim, got "
        f"{created['UserName']!r}"
    )
    assert iam.get_user(UserName=max_user)["User"]["UserName"] == max_user, (
        f"GetUser must echo the {MAX_USER_NAME}-character name it was just created with"
    )

    max_group = _pad(base_group, MAX_GROUP_NAME)
    iam.create_group(GroupName=max_group)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=max_group))
    assert iam.get_group(GroupName=max_group)["Group"]["GroupName"] == max_group, (
        f"a {MAX_GROUP_NAME}-character group name is legal and must round-trip"
    )

    max_policy = _pad(base_policy, MAX_POLICY_NAME)
    max_policy_arn = iam.create_policy(
        PolicyName=max_policy, PolicyDocument=ALLOW_S3_LIST
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=max_policy_arn))
    assert max_policy_arn.endswith("/" + max_policy), (
        f"a {MAX_POLICY_NAME}-character policy name is legal; ARN {max_policy_arn!r} must end with it"
    )

    # A 512-character path is legal (leading and trailing '/' included in the count).
    max_path = "/sim2real-behav/" + "p" * (MAX_PATH - len("/sim2real-behav/") - 1) + "/"
    assert len(max_path) == MAX_PATH, f"test setup bug: built path is {len(max_path)} chars, want {MAX_PATH}"
    path_user = ctx.unique_name("sim2real-behav-pu-")
    path_created = iam.create_user(UserName=path_user, Path=max_path)["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=path_user))
    assert path_created["Path"] == max_path, (
        f"a {MAX_PATH}-character path is legal and must round-trip, got {path_created['Path']!r}"
    )

    # ---------- rejected: one character over the maximum ----------
    over_user = _pad(base_user, MAX_USER_NAME + 1)
    _refused_exactly(
        lambda: iam.create_user(UserName=over_user),
        "ValidationError",
        (
            "1 validation error detected: Value at 'userName' failed to satisfy constraint: "
            f"Member must have length less than or equal to {MAX_USER_NAME}"
        ),
        f"CreateUser with a {MAX_USER_NAME + 1}-character user name",
    )

    # GetUser applies the CHARACTER-CLASS half of userNameType but NOT the length half, so:
    #   * a 65-character name reaches the lookup and comes back NoSuchEntity, and
    #   * a name containing '/' is refused before the lookup with ValidationError.
    # Both are asserted, because the pair is the actual contract and each direction alone is
    # satisfiable by an emulator that validates everything or nothing on reads.
    _refused_exactly(
        lambda: iam.get_user(UserName=over_user),
        "NoSuchEntity",
        f"The user with name {over_user} cannot be found.",
        f"GetUser with a {MAX_USER_NAME + 1}-character name (length is not enforced on reads)",
    )
    _refused_exactly(
        lambda: iam.get_user(UserName=base_user + "/tail"),
        "ValidationError",
        MSG_BAD_CHARSET,
        "GetUser with a '/' in the name (the character class is enforced on reads)",
    )

    over_group = _pad(base_group, MAX_GROUP_NAME + 1)
    _refused_exactly(
        lambda: iam.create_group(GroupName=over_group),
        "ValidationError",
        (
            "1 validation error detected: Value at 'groupName' failed to satisfy constraint: "
            f"Member must have length less than or equal to {MAX_GROUP_NAME}"
        ),
        f"CreateGroup with a {MAX_GROUP_NAME + 1}-character group name",
    )

    over_policy = _pad(base_policy, MAX_POLICY_NAME + 1)
    _refused_exactly(
        lambda: iam.create_policy(PolicyName=over_policy, PolicyDocument=ALLOW_S3_LIST),
        "ValidationError",
        (
            "1 validation error detected: Value at 'policyName' failed to satisfy constraint: "
            f"Member must have length less than or equal to {MAX_POLICY_NAME}"
        ),
        f"CreatePolicy with a {MAX_POLICY_NAME + 1}-character policy name",
    )

    over_path = "/sim2real-behav/" + "p" * (MAX_PATH - len("/sim2real-behav/")) + "/"
    assert len(over_path) == MAX_PATH + 1, f"test setup bug: built path is {len(over_path)} chars, want {MAX_PATH + 1}"
    _refused_exactly(
        lambda: iam.create_user(UserName=ctx.unique_name("sim2real-behav-op-"), Path=over_path),
        "ValidationError",
        (
            "1 validation error detected: Value at 'path' failed to satisfy constraint: "
            f"Member must have length less than or equal to {MAX_PATH}"
        ),
        f"CreateUser with a {MAX_PATH + 1}-character path",
    )

    # ---------- rejected: a character outside the name character class ----------
    for bad_char in BAD_NAME_CHARS:
        bad_user = base_user + bad_char + "tail"
        _refused_exactly(
            lambda n=bad_user: iam.create_user(UserName=n),
            "ValidationError",
            MSG_BAD_CHARSET,
            f"CreateUser with {bad_char!r} (outside userNameType's ^[\\w+=,.@-]+$ class)",
        )

    # ---------- rejected: a path missing its leading or trailing slash ----------
    for bad_path in ("sim2real-behav/", "/sim2real-behav", "sim2real-behav"):
        _refused_exactly(
            lambda p=bad_path: iam.create_user(
                UserName=ctx.unique_name("sim2real-behav-bp-"), Path=p
            ),
            "ValidationError",
            MSG_BAD_PATH,
            f"CreateUser with Path={bad_path!r} (pathType needs a leading AND trailing '/')",
        )

    # ---------- effect absent: none of the rejected creates left an entity behind ----------
    all_user_names = set()
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        all_user_names.update(u["UserName"] for u in page["Users"])
    leaked = {
        n
        for n in all_user_names
        if n.startswith(base_user) or n.startswith("sim2real-behav-bp-") or n.startswith("sim2real-behav-op-")
    } - {max_user}
    assert leaked == set(), (
        f"rejected CreateUser calls must persist nothing; these leaked into ListUsers: {sorted(leaked)}"
    )

    # ---------- control: after all the rejections, a legal create still works ----------
    ok_user = ctx.unique_name("sim2real-behav-ok-")
    iam.create_user(UserName=ok_user, Path="/sim2real-behav/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=ok_user))
    assert iam.get_user(UserName=ok_user)["User"]["Path"] == "/sim2real-behav/", (
        "a legal name and path must still be accepted after the rejection legs"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
