from permitd import binding_hash, canonical_args


def test_arg_order_and_whitespace_do_not_change_binding():
    assert binding_hash("t", {"a": 1, "b": 2}) == binding_hash("t", {"b": 2, "a": 1})
    assert canonical_args({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_any_value_change_changes_binding():
    assert binding_hash("t", {"to": "alice"}) != binding_hash("t", {"to": "eve"})


def test_tool_name_is_folded_in():
    assert binding_hash("send", {"x": 1}) != binding_hash("delete", {"x": 1})


def test_none_and_empty_args_are_equivalent():
    assert binding_hash("t", None) == binding_hash("t", {})
