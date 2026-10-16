from backend.crypto.key_generation import generate_file_key


def test_case1():
    key = generate_file_key()

    assert isinstance(key, bytes)

    assert len(key) == 32


def test2():

    key1 = generate_file_key()
    key2 = generate_file_key()

    assert key1 != key2
