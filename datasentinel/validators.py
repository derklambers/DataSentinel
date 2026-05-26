
"""
Validation helpers.
"""

def validate_bsn(bsn: str) -> bool:
    """
    Validate Dutch BSN using 11-test.
    """
    if len(bsn) == 8:
        bsn = "0" + bsn

    if len(bsn) != 9:
        return False

    total = 0

    for i in range(8):
        total += int(bsn[i]) * (9 - i)

    total -= int(bsn[-1])

    return total % 11 == 0


def validate_iban(iban: str) -> bool:
    """
    Validate Dutch IBAN checksum.
    """
    iban = iban.replace(" ", "").upper()

    rearranged = iban[4:] + iban[:4]

    numeric = ""

    for ch in rearranged:
        if ch.isalpha():
            numeric += str(ord(ch) - 55)
        else:
            numeric += ch

    return int(numeric) % 97 == 1
