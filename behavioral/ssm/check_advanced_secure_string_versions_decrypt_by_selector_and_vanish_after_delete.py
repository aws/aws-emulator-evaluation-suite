"""advanced-secure-string-versions-decrypt-by-selector-and-vanish-after-delete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "advanced-secure-string-versions-decrypt-by-selector-and-vanish-after-delete"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; FAILS on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get(
            "Message"
        ) or ""
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: answered HTTP {status!r}, expected 4xx"
    return code, message


def _settled(probe, done, timeout_s=30.0, interval_s=2.0):
    """probe() once done(answer) holds, or its last answer at the deadline (bounded read-only poll)."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if done(got) or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


def _read_state(ssm, selector):
    """("resolves", version) while GetParameter answers, else the refusal's (code, status, message)."""
    try:
        return "resolves", ssm.get_parameter(Name=selector, WithDecryption=True)["Parameter"]["Version"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""


def _described(ssm, name):
    return ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}])[
        "Parameters"
    ]


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Advanced-tier SecureString larger than the Standard limit, overwritten once, decrypts each
    version's own multibyte plaintext by selector and never returns it undecrypted; after
    DeleteParameter both selectors are refused ParameterNotFound and DescribeParameters lists nothing.
    """
    ssm = ctx.client("ssm")
    # A flat name: SSM stores and echoes it without a leading slash.
    name = ctx.unique_name("sim2real-behav-adv-secure-")
    # Multibyte text past the 4 KB Standard ceiling, so only the Advanced tier can hold it.
    first = "ключ-秘密-" * 300 + ctx.unique_name("a")
    second = "пароль-鍵-" * 280 + ctx.unique_name("b")
    assert 4096 < len(first.encode()) <= 8192 and 4096 < len(second.encode()) <= 8192, "test values out of range"
    ssm.put_parameter(Name=name, Value=first, Type="SecureString", Tier="Advanced")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, name))
    put = ssm.put_parameter(Name=name, Value=second, Type="SecureString", Tier="Advanced", Overwrite=True)
    assert (put["Version"], put["Tier"]) == (2, "Advanced"), f"the overwrite must mint Advanced version 2, got {put!r}"

    for selector, version, plaintext in ((f"{name}:1", 1, first), (f"{name}:2", 2, second), (name, 2, second)):
        got = ssm.get_parameter(Name=selector, WithDecryption=True)["Parameter"]
        assert (got["Version"], got["Type"]) == (version, "SecureString"), f"{selector}: got {got!r}"
        assert got["Value"] == plaintext, f"{selector} WithDecryption=True did not return version {version}'s plaintext"
        raw = ssm.get_parameter(Name=selector, WithDecryption=False)["Parameter"]["Value"]
        assert isinstance(raw, str) and raw and raw != plaintext and "ключ" not in raw and "пароль" not in raw, (
            f"{selector} WithDecryption=False must not return the plaintext"
        )
    want = [(name, "SecureString", "Advanced", 2)]

    def _rows(params):
        return [(p["Name"], p["Type"], p["Tier"], p["Version"]) for p in params]

    described = _settled(lambda: _described(ssm, name), lambda d: _rows(d) == want)
    assert _rows(described) == want, f"DescribeParameters must show one Advanced SecureString at version 2, got {described!r}"

    ssm.delete_parameter(Name=name)
    for selector in (name, f"{name}:1", f"{name}:2"):
        state = _settled(lambda s=selector: _read_state(ssm, s), lambda st: st[0] != "resolves")
        assert state[0] != "resolves", f"GetParameter({selector}) still resolves 30 s after the delete: {state!r}"
        got = _refusal(state, selector)
        assert got == ("ParameterNotFound", ""), f"GetParameter({selector}) after delete: got {got!r}"
    described = _settled(lambda: _described(ssm, name), lambda d: d == [])
    assert described == [], f"DescribeParameters still lists the deleted parameter: {described!r}"
    got = _refusal(
        _error(lambda: ssm.label_parameter_version(Name=name, ParameterVersion=2, Labels=["dead"])),
        "LabelParameterVersion on the deleted parameter",
    )
    assert got == ("ParameterNotFound", f"Parameter {name} not found."), (
        f"LabelParameterVersion on the deleted parameter: got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
