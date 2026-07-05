#!/bin/bash
# Test malware chain rules (100100-100104)
# Connects example.com (safe), not real C2
#
# Wazuh reality: each log line = separate event
# if_matched_sid checks same-decoded-event only
# -> cross-event chain never accumulates
#
# What actually fires:
#   100100 (create /tmp)        - matches on first event
#   100103 (curl|wget|nc)       - matches on network event
#   100104                      - fires if 100103 fired (no match filter)
#   100101 (chmod +x)           - may fire on chmod event IF decoded same as create
#   100102 (execve|bash|sh)     - same issue, per-event
#
# Full 5-stage chain never accumulates without frequency/timeframe

TEST_FILE="/tmp/.test_outbound_trigger.sh"

cat > "$TEST_FILE" << 'SCRIPT'
#!/bin/bash
curl -s --connect-timeout 5 http://example.com > /dev/null 2>&1 || \
wget -q --timeout=5 http://example.com -O /dev/null 2>&1 || \
nc -z -w5 example.com 80 2>&1
SCRIPT

chmod +x "$TEST_FILE"

echo "[*] Executing test chain..."
"$TEST_FILE"

rm -f "$TEST_FILE"
echo "[*] Cleanup done."
echo ""
echo "[*] Expected alerts:"
echo "    100100 - file created in /tmp"
echo "    100101 - chmod +x (if decoded with create event)"
echo "    100102 - execve/bash (if decoded with chmod event)"
echo "    100103 - outbound curl/wget/nc"
echo "    100104 - fires ONCE per network event (no match filter)"
echo ""
echo "[*] NOT expected: full 5-stage cross-event chain"
echo "    (needs frequency + timeframe for that)"
