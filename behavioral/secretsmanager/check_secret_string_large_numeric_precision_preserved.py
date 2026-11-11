"""secret-string-large-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secret-string-large-numeric-precision-preserved"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecretString holding a high-precision numeric literal is stored and returned as the
    exact same opaque string, with no numeric coercion or precision loss."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-numprecision-")

    # More significant digits than an IEEE-754 double (~17) can round-trip exactly; also
    # exercises leading zeros and a large exponent-free integer, which a naive JSON-number
    # storage path would mangle.
    numeric_literal = (
        "00012345678901234567890123456789012345678901234567890.123456789012345678901234567890"
    )

    sm.create_secret(Name=name, SecretString=numeric_literal)
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    put_resp = sm.put_secret_value(SecretId=name, SecretString=numeric_literal + "1")
    version_id = put_resp["VersionId"]

    got = sm.get_secret_value(SecretId=name, VersionId=version_id)
    assert got["SecretString"] == numeric_literal + "1", "high-precision numeric literal was mutated"

    got_current = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got_current["SecretString"] == numeric_literal + "1", (
        f"AWSCURRENT read did not match the stored high-precision literal: got "
        f"{got_current['SecretString']!r}"
    )
    assert not got_current["SecretString"].startswith("1.2345"), "value was coerced through a float"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
