from vibesec.rules.insecure_deserialization import check_insecure_deserialization


def test_detects_pickle_loads():
    assert check_insecure_deserialization("app.py", "pickle.loads(data)")


def test_detects_yaml_load_without_loader():
    assert check_insecure_deserialization("app.py", "yaml.load(data)")


def test_detects_marshal_loads():
    assert check_insecure_deserialization("app.py", "marshal.loads(blob)")


def test_allows_yaml_safe_load():
    assert check_insecure_deserialization("app.py", "yaml.safe_load(data)") == []


def test_allows_yaml_safe_loader():
    assert check_insecure_deserialization("app.py", "yaml.load(data, Loader=yaml.SafeLoader)") == []


def test_allows_hardcoded_pickle_bytes_edge_case():
    assert check_insecure_deserialization("app.py", "pickle.loads(b'abc')") == []
