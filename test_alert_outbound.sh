#!/bin/bash
# Test outbound alert rule 100103
# Creates file in /tmp, chmod +x, executes, connects safe host
# Triggers 100100 -> 100101 -> 100102 -> 100103
# Uses example.com (safe, IANA reserved) not C2

TEST_FILE="/tmp/.test_outbound_trigger.sh"

cat > "$TEST_FILE" << 'SCRIPT'
#!/bin/bash
# Safe outbound to example.com (triggers 100103 via curl|wget|nc)
curl -s --connect-timeout 5 http://example.com > /dev/null 2>&1 || \
wget -q --timeout=5 http://example.com -O /dev/null 2>&1 || \
nc -z -w5 example.com 80 2>&1
SCRIPT

chmod +x "$TEST_FILE"

echo "[*] Executing test chain. Alerts 100100->100101->100102->100103 should fire."
"$TEST_FILE"

rm -f "$TEST_FILE"
echo "[*] Cleanup done. 100104 should NOT fire (safe destination)."
