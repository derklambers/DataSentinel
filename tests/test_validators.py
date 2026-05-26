
from datasentinel.validators import validate_bsn, validate_iban

def test_invalid_bsn():
    assert validate_bsn("111222333") is False

def test_valid_iban():
    assert validate_iban("NL91ABNA0417164300") is True
