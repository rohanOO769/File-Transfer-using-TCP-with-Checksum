# test_client.py

import pytest
import tempfile
import os
from client import main as client_main

@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(b"Hello, world!")
        temp_path = temp.name
    yield temp_path
    os.remove(temp_path)

def test_client_sends_file(temp_file):
    """Test if the client sends a file correctly."""
    try:
        client_main(temp_file)
    except Exception as e:
        pytest.fail(f"Client failed to send file: {e}")
