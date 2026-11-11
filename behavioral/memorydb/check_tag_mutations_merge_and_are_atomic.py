"""tag-mutations-merge-and-are-atomic."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-mutations-merge-and-are-atomic"
GROUP = 'tagging'
SERVICES = ['memorydb']

_WAIT_TIMEOUT_S = 600


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_when_settled(fn, not_found: str, busy: str) -> None:
    """Delete once the resource leaves a transitional state; a not-found means already gone."""
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == not_found:
                return
            if code != busy or time.monotonic() > deadline:
                raise
        time.sleep(3)


def _wait_user_active(m, name: str) -> dict:
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        user = m.describe_users(UserName=name)["Users"][0]
        if user["Status"] == "active":
            return user
        assert time.monotonic() < deadline, f"user {name!r} stuck in status {user['Status']!r}"
        time.sleep(3)


def _wait_acl_active(m, name: str) -> dict:
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        acl = m.describe_acls(ACLName=name)["ACLs"][0]
        if acl["Status"] == "active":
            return acl
        assert time.monotonic() < deadline, f"ACL {name!r} stuck in status {acl['Status']!r}"
        time.sleep(3)


def _drop_user(m, name: str) -> None:
    _delete_when_settled(lambda: m.delete_user(UserName=name), "UserNotFoundFault", "InvalidUserStateFault")


def _drop_acl(m, name: str) -> None:
    _delete_when_settled(lambda: m.delete_acl(ACLName=name), "ACLNotFoundFault", "InvalidACLStateFault")


def _tags(m, arn: str) -> dict:
    return {t["Key"]: t.get("Value") for t in m.list_tags(ResourceArn=arn)["TagList"]}


def _drop_pg(m, name: str) -> None:
    try:
        m.delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterGroupNotFoundFault":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a user, an ACL and a parameter group, create-time tags list back, TagResource merges by key and
    returns the full set, a valueless tag reads as "", UntagResource naming one absent key removes
    nothing, and an aws: key is refused.
    """
    m = ctx.client("memorydb")
    name = ctx.unique_name("sim2real-mdb-")
    seed = [{"Key": "sim2real", "Value": CHECK}, {"Key": "keep", "Value": "1"}]
    arns = {
        "user": m.create_user(UserName=name, AccessString="on ~* +@all", Tags=seed,
                              AuthenticationMode={"Type": "password", "Passwords": ["Sim2realPassword-1"]})["User"]["ARN"],
    }
    ctx.on_cleanup(lambda: _drop_user(m, name))
    arns["acl"] = m.create_acl(ACLName=name, Tags=seed)["ACL"]["ARN"]
    ctx.on_cleanup(lambda: _drop_acl(m, name))
    arns["parametergroup"] = m.create_parameter_group(
        ParameterGroupName=name, Family="memorydb_redis7", Tags=seed)["ParameterGroup"]["ARN"]
    ctx.on_cleanup(lambda: _drop_pg(m, name))

    for kind, arn in arns.items():
        assert arn == f"arn:aws:memorydb:{ctx.region}:{ctx.account}:{kind}/{name}", f"{kind} ARN has the wrong form"
        assert _tags(m, arn) == {"sim2real": CHECK, "keep": "1"}, f"{kind}: create-time tags {_tags(m, arn)!r}"

        out = m.tag_resource(ResourceArn=arn, Tags=[{"Key": "keep", "Value": "2"}, {"Key": "bare"}])["TagList"]
        merged = {"sim2real": CHECK, "keep": "2", "bare": ""}
        assert {t["Key"]: t.get("Value") for t in out} == merged, f"{kind}: TagResource returned {out!r}"
        assert _tags(m, arn) == merged, f"{kind}: merged tags read back {_tags(m, arn)!r}"

        code, msg = _error(lambda a=arn: m.untag_resource(ResourceArn=a, TagKeys=["keep", "absent"]))
        assert code == "TagNotFoundFault", f"{kind}: untag with an absent key gave {code}: {msg!r}"
        assert msg == "Failing request. These tags are not present : absent", f"{kind}: message was {msg!r}"
        assert _tags(m, arn) == merged, f"{kind}: a refused untag removed tags: {_tags(m, arn)!r}"

        code, msg = _error(lambda a=arn: m.tag_resource(ResourceArn=a, Tags=[{"Key": "aws:owner", "Value": "x"}]))
        assert code == "InvalidParameterValueException", f"{kind}: aws: key gave {code}: {msg!r}"
        assert msg == 'Tag keys cannot start with the reserved prefix "aws:".', f"{kind}: message was {msg!r}"

        out = m.untag_resource(ResourceArn=arn, TagKeys=["keep"])["TagList"]
        assert {t["Key"]: t.get("Value") for t in out} == {"sim2real": CHECK, "bare": ""}, f"{kind}: untag returned {out!r}"
        assert _tags(m, arn) == {"sim2real": CHECK, "bare": ""}, f"{kind}: tags after untag {_tags(m, arn)!r}"

    default_arn = f"arn:aws:memorydb:{ctx.region}:{ctx.account}:parametergroup/default.memorydb-redis7"
    code, msg = _error(lambda: m.tag_resource(ResourceArn=default_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert (code, msg) == ("InvalidParameterValueException", "Tagging on default resources is not supported"), (
        f"tagging a default group gave {code}: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
