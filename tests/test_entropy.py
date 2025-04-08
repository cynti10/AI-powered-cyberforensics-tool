from engine.feature_extractor import calculate_entropy

def test_entropy_zero():
    assert calculate_entropy(b"") == 0.0

def test_entropy_known():
    data = b"AAAAAAAABBBBBBBBCCCCCCCC"
    assert round(calculate_entropy(data), 2) == 1.58
