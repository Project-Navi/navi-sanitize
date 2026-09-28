# tests/test_walk.py
"""Tests for the walk() recursive sanitizer."""

from __future__ import annotations

import logging

import pytest


class TestWalkDict:
    def test_sanitizes_string_values(self) -> None:
        from navi_sanitize import walk

        data = {"name": "n\u0430vi", "count": 42}
        result = walk(data)
        assert result["name"] == "navi"
        assert result["count"] == 42

    def test_deep_copy(self) -> None:
        from navi_sanitize import walk

        data = {"name": "n\u0430vi"}
        result = walk(data)
        assert result is not data
        assert data["name"] == "n\u0430vi"  # original unchanged

    def test_nested_dicts(self) -> None:
        from navi_sanitize import walk

        data = {"outer": {"inner": "te\x00st"}}
        result = walk(data)
        assert result["outer"]["inner"] == "test"

    def test_preserves_non_strings(self) -> None:
        from navi_sanitize import walk

        data = {"flag": True, "count": 42, "ratio": 3.14, "empty": None}
        result = walk(data)
        assert result == data


class TestWalkList:
    def test_sanitizes_list_strings(self) -> None:
        from navi_sanitize import walk

        data = ["n\u0430vi", "te\x00st"]
        result = walk(data)
        assert result == ["navi", "test"]

    def test_nested_lists(self) -> None:
        from navi_sanitize import walk

        data = [["n\u0430vi"], ["te\x00st"]]
        result = walk(data)
        assert result == [["navi"], ["test"]]


class TestWalkMixed:
    def test_dict_with_list_values(self) -> None:
        from navi_sanitize import walk

        data = {"names": ["n\u0430vi", "hello"], "count": 3}
        result = walk(data)
        assert result["names"] == ["navi", "hello"]
        assert result["count"] == 3

    def test_list_of_dicts(self) -> None:
        from navi_sanitize import walk

        data = [{"name": "te\x00st"}, {"name": "hello"}]
        result = walk(data)
        assert result[0]["name"] == "test"
        assert result[1]["name"] == "hello"


class TestWalkWithEscaper:
    def test_escaper_applied_to_all_strings(self) -> None:
        from navi_sanitize import jinja2_escaper, walk

        data = {"a": "{{ x }}", "b": "safe", "c": ["{{ y }}"]}
        result = walk(data, escaper=jinja2_escaper)
        assert "{{" not in result["a"]
        assert result["b"] == "safe"
        assert "{{" not in result["c"][0]


class TestWalkEdgeCases:
    def test_empty_dict(self) -> None:
        from navi_sanitize import walk

        assert walk({}) == {}

    def test_empty_list(self) -> None:
        from navi_sanitize import walk

        assert walk([]) == []

    def test_plain_string(self) -> None:
        from navi_sanitize import walk

        assert walk("n\u0430vi") == "navi"

    def test_non_string_scalar(self) -> None:
        from navi_sanitize import walk

        assert walk(42) == 42

    def test_warns_on_hostile_values(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk({"name": "n\u0430vi\x00"})
        assert "homoglyph" in caplog.text.lower()
        assert "null byte" in caplog.text.lower()


class TestWalkDepthLimit:
    def test_max_depth_exceeded_warns_and_continues(self, caplog: pytest.LogCaptureFixture) -> None:
        """walk() never crashes on deep input — it warns and sanitizes."""
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(129):
            data = {"k": data}
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data)
        assert "max_depth=128" in caplog.text
        # Leaf string is still sanitized despite exceeding depth
        node: object = result
        for _ in range(129):
            assert isinstance(node, dict)
            node = node["k"]
        assert node == "navi"

    def test_default_max_depth_accepts_shallow(self) -> None:
        from navi_sanitize import walk

        result = walk({"a": {"b": "n\u0430vi"}})
        assert result["a"]["b"] == "navi"

    def test_custom_max_depth_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(10):
            data = {"k": data}
        # Exactly 10 — no warning
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk(data, max_depth=10)
        assert "max_depth" not in caplog.text

    def test_custom_max_depth_exceeded_still_sanitizes(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(11):
            data = {"k": data}
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data, max_depth=10)
        assert "max_depth=10" in caplog.text
        # Leaf is still sanitized
        node: object = result
        for _ in range(11):
            assert isinstance(node, dict)
            node = node["k"]
        assert node == "navi"

    def test_max_depth_zero_warns_on_containers(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk({"a": "n\u0430vi"}, max_depth=0)
        assert "max_depth=0" in caplog.text
        assert result["a"] == "navi"  # still sanitized

    def test_max_depth_zero_accepts_scalar(self) -> None:
        from navi_sanitize import walk

        assert walk("n\u0430vi", max_depth=0) == "navi"
        assert walk(42, max_depth=0) == 42

    def test_max_depth_negative_raises(self) -> None:
        from navi_sanitize import walk

        with pytest.raises(ValueError, match="max_depth must be >= 0"):
            walk({}, max_depth=-1)

    def test_max_depth_list_path_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(11):
            data = [data]
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data, max_depth=10)
        assert "max_depth=10" in caplog.text
        node: object = result
        for _ in range(11):
            assert isinstance(node, list)
            node = node[0]
        assert node == "navi"

    def test_max_depth_with_escaper(self) -> None:
        from navi_sanitize import jinja2_escaper, walk

        data = {"a": {"b": "{{ x }}"}}
        result = walk(data, escaper=jinja2_escaper, max_depth=10)
        assert "{{" not in result["a"]["b"]

    def test_iterative_walker_handles_any_depth(self) -> None:
        """5000-deep structure is sanitized without crashing.

        The iterative walker uses an explicit stack (heap memory),
        not Python's call stack, so no RecursionError is possible.
        """
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(5000):
            data = {"k": data}
        result = walk(data, max_depth=10000)
        node: object = result
        for _ in range(5000):
            assert isinstance(node, dict)
            node = node["k"]
        assert node == "navi"

    def test_shared_substructure_sanitized_once(self) -> None:
        """A shared node is copied and sanitized exactly once."""
        from navi_sanitize import walk

        shared: dict[str, object] = {"name": "n\u0430vi"}
        root = {"a": shared, "b": shared}
        result = walk(root)
        assert result["a"]["name"] == "navi"
        assert result["b"]["name"] == "navi"
        # Both point to the same sanitized copy
        assert result["a"] is result["b"]

    def test_tuples_pass_through_by_reference(self) -> None:
        """Tuples are not traversed — strings inside are NOT sanitized."""
        from navi_sanitize import walk

        data = {"key": ("n\u0430vi",)}
        result = walk(data, max_depth=10)
        assert result["key"] == ("n\u0430vi",)

    def test_never_crashes_on_any_depth(self) -> None:
        """walk() always returns output, never raises on data shape."""
        from navi_sanitize import walk

        data: object = "n\u0430vi"
        for _ in range(1000):
            data = {"k": data}
        # Must not raise — walk() always returns
        result = walk(data)
        assert isinstance(result, dict)

    def test_diamond_dag_sanitized_consistently(self) -> None:
        """Diamond-shaped DAG: A -> B, A -> C, B -> D, C -> D.

        D is reachable via two paths. The walker must sanitize D
        exactly once and both paths must see the same sanitized copy.
        """
        from navi_sanitize import walk

        d: dict[str, object] = {"val": "n\u0430vi"}
        b: dict[str, object] = {"d": d, "own": "te\x00st"}
        c: dict[str, object] = {"d": d, "own": "\u200bhidden"}
        a = {"b": b, "c": c}
        result = walk(a)
        assert result["b"]["d"]["val"] == "navi"
        assert result["c"]["d"]["val"] == "navi"
        assert result["b"]["d"] is result["c"]["d"]
        assert result["b"]["own"] == "test"
        assert result["c"]["own"] == "hidden"

    def test_alternating_dict_list_depth(self) -> None:
        """Dict-list-dict-list nesting — the real shape of JSON APIs."""
        from navi_sanitize import walk

        data: object = "p\u0430yload"
        for i in range(50):
            data = [data] if i % 2 else {"k": data}
        result = walk(data)
        node: object = result
        for i in range(50):
            if (49 - i) % 2:
                assert isinstance(node, list)
                node = node[0]
            else:
                assert isinstance(node, dict)
                node = node["k"]
        assert node == "payload"

    def test_original_never_mutated(self) -> None:
        """The original structure must be completely untouched."""
        from navi_sanitize import walk

        inner = {"name": "n\u0430vi\x00", "tags": ["\u200bhidden"]}
        original = {"user": inner, "count": 42}
        walk(original)
        # Every hostile character survives in the original
        assert original["user"]["name"] == "n\u0430vi\x00"
        assert original["user"]["tags"][0] == "\u200bhidden"
        assert original["count"] == 42

    def test_mutual_cycle_two_dicts(self) -> None:
        """Two dicts that reference each other — mutual cycle."""
        from navi_sanitize import walk

        a: dict[str, object] = {"name": "\u0430lpha"}
        b: dict[str, object] = {"name": "\u043emega", "friend": a}
        a["friend"] = b
        result = walk(a)
        assert result["name"] == "alpha"
        assert result["friend"]["name"] == "omega"
        assert result["friend"]["friend"] is result  # cycle preserved

    def test_empty_containers_at_depth(self) -> None:
        """Empty dicts/lists at various depths — no crash, no skip."""
        from navi_sanitize import walk

        data = {"a": {}, "b": [], "c": {"d": [], "e": {}}}
        result = walk(data)
        assert result == {"a": {}, "b": [], "c": {"d": [], "e": {}}}
        assert result is not data

    def test_hostile_keys_and_values_simultaneously(self) -> None:
        """Keys with homoglyphs, values with invisibles, nested."""
        from navi_sanitize import walk

        data = {
            "n\u0430me": "v\u0430lue",
            "\x00key": {"inner\u200b": ["\u0430", "\x00"]},
        }
        result = walk(data)
        assert "name" in result
        assert result["name"] == "value"
        assert "key" in result
        assert "inner" in result["key"]
        assert result["key"]["inner"] == ["a", ""]


def _collision_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "collision" in r.getMessage()]


class TestWalkKeyCollisions:
    """Distinct keys that sanitize to the same key: last value wins, with a warning."""

    def test_homoglyph_collision_keeps_last_value_and_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from navi_sanitize import walk

        data = {"a": 1, "\u0430": 2}
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data)
        assert result == {"a": 2}
        assert data == {"a": 1, "\u0430": 2}
        records = _collision_records(caplog)
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert records[0].args == (1,)

    def test_escaper_collision_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk({"Key": 1, "KEY": 2, "key": 3, "other": 4}, escaper=str.lower)
        assert result == {"key": 3, "other": 4}
        assert list(result) == ["key", "other"]  # first-insertion position retained
        records = _collision_records(caplog)
        assert len(records) == 1
        assert records[0].args == (2,)

    def test_one_warning_per_affected_dict(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        data = [{"x": 1, "x\u200b": 2}, {"clean": 1}, {"y\x00": 1, "y": 2}]
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data)
        assert result == [{"x": 2}, {"clean": 1}, {"y": 2}]
        assert len(_collision_records(caplog)) == 2

    def test_no_warning_without_collision(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.DEBUG, logger="navi_sanitize"):
            walk({"a": 1, "b\u200b": 2, 3: "c", None: "d"})
        assert not _collision_records(caplog)

    def test_non_string_keys_do_not_collide_with_strings(self) -> None:
        from navi_sanitize import walk

        assert walk({1: "a", "1": "b", (1,): "c"}) == {1: "a", "1": "b", (1,): "c"}

    def test_collision_log_is_content_free(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        secret = "COLLISION_SENTINEL_KEY"
        with caplog.at_level(logging.DEBUG, logger="navi_sanitize"):
            walk({secret + "\u200b": "SENTINEL_VALUE_1", secret: "SENTINEL_VALUE_2"})
        assert _collision_records(caplog)
        for record in caplog.records:
            text = record.getMessage() + repr(record.args)
            assert "SENTINEL" not in text

    def test_collision_with_aliased_and_cyclic_values(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from navi_sanitize import walk

        shared = ["s\u200b"]
        data: dict[str, object] = {"k": shared, "k\u200b": shared, "alias": shared}
        data["self"] = data
        data["self\x00"] = data
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data)
        assert set(result) == {"k", "alias", "self"}
        assert result["k"] is result["alias"]
        assert result["k"] == ["s"]
        assert result["self"] is result
        assert shared == ["s\u200b"]
        assert set(data) == {"k", "k\u200b", "alias", "self", "self\x00"}
        records = _collision_records(caplog)
        assert len(records) == 1
        assert records[0].args == (2,)

    def test_collision_check_adds_no_key_lookups(self) -> None:
        """Counting collisions must not hash or compare keys beyond the copy itself."""
        from navi_sanitize import walk

        class Probe:
            hashes = 0

            def __hash__(self) -> int:
                Probe.hashes += 1
                return 7

            def __eq__(self, other: object) -> bool:
                return self is other

        k1, k2 = Probe(), Probe()
        data = {k1: "a", k2: "b"}
        Probe.hashes = 0
        result = walk(data)
        assert Probe.hashes == 2  # one insertion per key, as before collision counting
        assert list(result) == [k1, k2]
        assert list(result.values()) == ["a", "b"]


class TestWalkDepthSemantics:
    """max_depth is an advisory threshold on first-discovery depth."""

    def test_threshold_counts_from_zero_at_top_level(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk({"a": {"b": "x"}}, max_depth=2)  # containers at depth 0 and 1
        assert "max_depth" not in caplog.text
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk({"a": {"b": {"c": "x"}}}, max_depth=2)  # a container at depth 2
        assert "max_depth=2" in caplog.text

    def test_shared_container_measured_where_first_reached(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A shared container is visited once, at the depth where walk() first reaches it."""
        from navi_sanitize import walk

        shared = {"value": "ok"}
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk({"deep": {"nested": shared}, "shallow": shared}, max_depth=2)
        assert "max_depth" not in caplog.text
        assert result["deep"]["nested"] is result["shallow"]
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk({"deep": {"nested": {"value": "ok"}}, "shallow": {"value": "ok"}}, max_depth=2)
        assert "max_depth=2" in caplog.text

    def test_single_warning_per_call(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk([[["a"], ["b"]], [["c"]]], max_depth=1)
        assert caplog.text.count("max_depth=1") == 1


class TestWalkContainerCopies:
    """walk() copies traversed dicts/lists only; other objects are shared, not deep-copied."""

    def test_subclasses_rebuilt_as_plain_containers(self) -> None:
        from collections import OrderedDict, defaultdict

        from navi_sanitize import walk

        ordered = walk(OrderedDict([("k", "v\u200b")]))
        assert type(ordered) is dict
        assert ordered == {"k": "v"}
        default: defaultdict[str, list[str]] = defaultdict(list, {"k": ["v\u200b"]})
        rebuilt = walk(default)
        assert type(rebuilt) is dict
        assert rebuilt == {"k": ["v"]}

    def test_untraversed_objects_keep_identity(self) -> None:
        from navi_sanitize import walk

        opaque = [("a\u200b",), {"a\u200b"}, frozenset({"a\u200b"}), b"a\x00", bytearray(b"x")]
        for item in opaque:
            assert walk(item) is item
            assert walk({"x": item})["x"] is item
            assert walk([item])[0] is item
