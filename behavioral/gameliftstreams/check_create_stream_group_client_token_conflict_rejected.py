"""create-stream-group-client-token-conflict-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-group-client-token-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken with DIFFERENT CreateStreamGroup parameters is rejected with
    ConflictException, the original resource is left untouched, and reusing the token with the
    ORIGINAL parameters still succeeds idempotently (positive control)."""
    gls = ctx.client("gameliftstreams")
    token = uuid.uuid4().hex
    description_a = ctx.unique_name("sim2real-behav-gls-sg-a-")
    description_b = ctx.unique_name("sim2real-behav-gls-sg-b-")

    tags = {"sim2real:managed": "true"}
    locations = [{"LocationName": ctx.region, "MaximumCapacity": 2}]
    try:
        first = gls.create_stream_group(
            Description=description_a,
            StreamClass="gen4n_high",
            LocationConfigurations=locations,
            ClientToken=token,
            Tags=tags,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gls, first["Arn"]))

    code, message = _error_code(
        lambda: gls.create_stream_group(
            Description=description_b,
            StreamClass="gen4n_high",
            LocationConfigurations=locations,
            ClientToken=token,
        )
    )
    assert code == "ConflictException", (
        f"reusing a ClientToken with a DIFFERENT Description must be rejected with "
        f"ConflictException; got {code!r}"
    )
    expected = "'ClientToken' value has already been used with different request parameters"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: the original resource's description was not changed/replaced
    reread = gls.get_stream_group(Identifier=first["Arn"])
    assert reread["Description"] == description_a, (
        f"the rejected conflicting call must not mutate the original resource; expected "
        f"Description {description_a!r}, got {reread['Description']!r}"
    )

    # positive control: reusing the token with the ORIGINAL parameters succeeds idempotently
    replay = gls.create_stream_group(
        Description=description_a,
        StreamClass="gen4n_high",
        LocationConfigurations=locations,
        ClientToken=token,
        Tags=tags,
    )
    assert replay["Arn"] == first["Arn"], (
        f"replaying the ClientToken with the ORIGINAL parameters must be idempotent; expected "
        f"Arn {first['Arn']!r}, got {replay['Arn']!r}"
    )
    assert replay["Id"] == first["Id"], (
        f"replaying the ClientToken with the ORIGINAL parameters must be idempotent; expected "
        f"Id {first['Id']!r}, got {replay['Id']!r}"
    )

    # terminal read: an INDEPENDENT list operation, at the destination, proves neither the
    # rejected conflict nor the idempotent replay left a second stream group behind.
    matching = [g for g in _list_all_stream_groups(gls) if g.get("Id") == first["Id"]]
    assert len(matching) == 1, (
        f"expected exactly one stream group with Id {first['Id']!r} to exist after the "
        f"rejected conflict and the idempotent replay, found {len(matching)}: {matching!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected ConflictException from the conflicting CreateStreamGroup call, but it "
        f"succeeded and returned {result!r}"
    )


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


def _delete_stream_group_when_settled(gls, arn, timeout_s=1800.0, interval_s=15.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gls.delete_stream_group(Identifier=arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        try:
            gls.get_stream_group(Identifier=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream group {arn} still present after {timeout_s}s")
        time.sleep(interval_s)


def _list_all_stream_groups(gls):
    items = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = gls.list_stream_groups(**kwargs)
        items.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
