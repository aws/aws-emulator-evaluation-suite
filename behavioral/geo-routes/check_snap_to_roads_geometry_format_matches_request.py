"""snap-to-roads-geometry-format-matches-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-geometry-format-matches-request"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_TRACE_POINTS = [
    {"Position": [-122.3366, 47.6101]},
    {"Position": [-122.3363, 47.6111]},
    {"Position": [-122.3360, 47.6121]},
]


# Minimal decoder for the HERE "flexible-polyline" format
# (https://github.com/heremaps/flexible-polyline), which is what
# SnappedGeometryFormat="FlexiblePolyline" encodes onto the wire. Verified
# against the spec's own worked example before use here.
_FP_DECODING_TABLE = [-1] * 78
_FP_DECODING_TABLE[0] = 62  # '-'
for _i, _v in enumerate(range(52, 62)):
    _FP_DECODING_TABLE[3 + _i] = _v  # '0'-'9'
for _i, _v in enumerate(range(0, 26)):
    _FP_DECODING_TABLE[20 + _i] = _v  # 'A'-'Z'
_FP_DECODING_TABLE[50] = 63  # '_'
for _i, _v in enumerate(range(26, 52)):
    _FP_DECODING_TABLE[52 + _i] = _v  # 'a'-'z'


def _fp_decode_char(c: str) -> int:
    idx = ord(c) - 45
    if idx < 0 or idx >= len(_FP_DECODING_TABLE):
        return -1
    return _FP_DECODING_TABLE[idx]


def _fp_decode_unsigned_values(encoded: str) -> list[int]:
    result = 0
    shift = 0
    out = []
    for c in encoded:
        v = _fp_decode_char(c)
        assert v != -1, f"flexible-polyline: byte {c!r} is outside the encoding alphabet"
        result |= (v & 0x1F) << shift
        if (v & 0x20) == 0:
            out.append(result)
            result = 0
            shift = 0
        else:
            shift += 5
    return out


def _fp_to_signed(value: int) -> int:
    is_negative = (value & 1) == 1
    value >>= 1
    return ~value if is_negative else value


def _fp_decode(encoded: str) -> tuple[list[tuple[float, float]], int]:
    """Returns ([(lat, lng), ...], precision)."""
    vals = _fp_decode_unsigned_values(encoded)
    version, header = vals[0], vals[1]
    assert version == 1, f"flexible-polyline: expected header version 1, got {version}"
    precision = header & 15
    third_dim = (header >> 4) & 7
    third_dim_precision = (header >> 7) & 15
    factor = 10**precision
    factor_z = 10**third_dim_precision
    last_lat = last_lng = last_z = 0
    points = []
    i = 2
    while i < len(vals):
        last_lat += _fp_to_signed(vals[i])
        last_lng += _fp_to_signed(vals[i + 1])
        i += 2
        if third_dim:
            last_z += _fp_to_signed(vals[i])
            i += 1
        points.append((last_lat / factor, last_lng / factor))
    return points, precision


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnappedGeometryFormat controls the wire shape of SnappedGeometry: Simple yields
    a decoded LineString of [lon, lat] pairs, FlexiblePolyline yields an encoded
    string -- and the two are mutually exclusive on the same underlying geometry."""
    client = ctx.client("geo-routes")

    simple = client.snap_to_roads(
        TracePoints=_TRACE_POINTS, SnappedGeometryFormat="Simple"
    )
    assert simple["SnappedGeometryFormat"] == "Simple", (
        f"expected SnappedGeometryFormat=Simple, got {simple.get('SnappedGeometryFormat')!r}"
    )
    simple_geometry = simple["SnappedGeometry"]
    assert "LineString" in simple_geometry, f"Simple response missing LineString: {simple_geometry!r}"
    assert "Polyline" not in simple_geometry, (
        f"Simple response must not also carry Polyline: {simple_geometry!r}"
    )
    line = simple_geometry["LineString"]
    assert len(line) >= 2, f"expected a multi-point LineString, got {len(line)} point(s)"
    for point in line:
        assert len(point) == 2, f"expected [lon, lat] pairs, got {point!r}"

    polyline_resp = client.snap_to_roads(
        TracePoints=_TRACE_POINTS, SnappedGeometryFormat="FlexiblePolyline"
    )
    assert polyline_resp["SnappedGeometryFormat"] == "FlexiblePolyline", (
        f"expected SnappedGeometryFormat=FlexiblePolyline, got {polyline_resp.get('SnappedGeometryFormat')!r}"
    )
    polyline_geometry = polyline_resp["SnappedGeometry"]
    assert "Polyline" in polyline_geometry, f"FlexiblePolyline response missing Polyline: {polyline_geometry!r}"
    assert "LineString" not in polyline_geometry, (
        f"FlexiblePolyline response must not also carry LineString: {polyline_geometry!r}"
    )
    encoded = polyline_geometry["Polyline"]
    assert isinstance(encoded, str), f"expected Polyline to be a string, got {type(encoded)!r}"
    assert len(encoded) > 0, "expected a non-empty encoded Polyline"

    # The two formats are two encodings of the *same* snapped geometry, not two
    # independently-shaped responses -- decode the polyline and demand it lines
    # up with the LineString points from the Simple call above.
    decoded_points, precision = _fp_decode(encoded)
    assert len(decoded_points) == len(line), (
        f"decoded Polyline has {len(decoded_points)} point(s), "
        f"Simple LineString has {len(line)} -- same geometry, different format, must match"
    )
    tolerance = 1.5 * (10**-precision)
    for idx, ((lon, lat), (d_lat, d_lng)) in enumerate(zip(line, decoded_points)):
        assert abs(lat - d_lat) < tolerance and abs(lon - d_lng) < tolerance, (
            f"point {idx}: Simple gave (lon={lon}, lat={lat}), "
            f"decoded Polyline gave (lat={d_lat}, lng={d_lng}) -- outside tolerance {tolerance}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
