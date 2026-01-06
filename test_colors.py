
from dashboard import get_color_for_attack, PALETTE, FALLBACK_PALETTE

print("Testing Custom Palette...")
# Helper to check hex
def get_hex(attack):
    return get_color_for_attack(attack)[0]

# Known Mappings
assert get_hex("SQL Injection") == "#D62728" # Danger Red
assert get_hex("API Abuse") == "#1F77B4" # Strong Blue
assert get_hex("Clickjacking") == "#8C564B" # Chestnut Brown
assert get_hex("Normal Traffic") == "#7F7F7F" # Steel Gray

# Keyword Match
assert get_hex("Some SQL Mal") == "#D62728"
assert get_hex("Random SSH Attack") == "#B11226" # Crimson (mapped manually)
print("Mappings passed.")

# Fallback
u1 = get_color_for_attack("Unknown-1")
assert u1 in FALLBACK_PALETTE
print("Fallback passed.")

print("All custom palette tests passed.")
