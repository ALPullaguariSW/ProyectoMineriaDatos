import pytest
import os
import joblib
from src.predict import predict_file
from src.preprocessing import clean_code

# Mock model and vectorizer for testing without loading full files
class MockModel:
    def predict(self, X):
        return [0] # Always predict safe
    def predict_proba(self, X):
        return [[0.9, 0.1]] # High confidence safe

class MockVectorizer:
    def transform(self, text):
        return [[0]] # Dummy feature

def test_robustness_empty_file(tmp_path):
    """Test handling of an empty file."""
    f = tmp_path / "empty.c"
    f.write_text("", encoding="utf-8")
    
    # We use real predict_file but with mocked model to isolate file handling
    model = MockModel()
    vec = MockVectorizer()
    
    # Should not crash
    pred, prob = predict_file(str(f), model, vec)
    assert pred == 0

def test_robustness_weird_chars(tmp_path):
    """Test handling of files with non-utf-8 or weird characters."""
    f = tmp_path / "weird.c"
    # Write some binary/weird data
    with open(f, "wb") as binary_file:
        binary_file.write(b"\x80\x81\xff")
        
    model = MockModel()
    vec = MockVectorizer()
    
    # predict_file opens with 'utf-8' by default in our implementation?
    # Let's check implementation. It uses 'r' and 'utf-8'.
    # This might raise UnicodeDecodeError. Ideally our code should handle it.
    # If it crashes, we found a bug to fix!
    try:
        predict_file(str(f), model, vec)
    except UnicodeDecodeError:
        pytest.fail("System crashed on non-UTF8 file")
    except Exception:
        pass # Other errors might be acceptable, but crash is not.

def test_clean_code_robustness():
    """Test clean_code with edge cases."""
    assert clean_code("") == ""
    assert clean_code("   ") == ""
    assert clean_code(None) == "" # Should probably handle None if passed
    assert clean_code("int main() { return 0; }") == "int main() { return 0; }"
