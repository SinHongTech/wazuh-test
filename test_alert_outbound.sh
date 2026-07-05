#!/bin/bash
# Test malware chain with frequency/timeframe cross-event correlation
#
# Corrected Wazuh rules (add to your local_rules.xml):
#
# <group name="custom,malware,">
#   <rule id="100100" level="5">
#     <match>/tmp</match>
#     <description>File created in /tmp directory</description>
#   </rule>
#
#   <rule id="100101" level="7">
#     <match>chmod.*\+x</match>
#     <description>File in /tmp made executable</description>
#   </rule>
#
#   <rule id="100102" level="8">
#     <match>execve|bash|sh</match>
#     <description>Execution of file from temporary directory</description>
#   </rule>
#
#   <rule id="100103" level="10">
#     <match>curl|wget|nc</match>
#     <description>Outbound network connection detected</description>
#   </rule>
#
#   <rule id="100104" level="15">
#     <if_matched_sid>100100</if_matched_sid>
#     <match>/tmp</match>
#     <frequency>4</frequency>
#     <timeframe>60</timeframe>
#     <description>4+ suspicious /tmp events within 60s - possible malware chain</description>
#     <mitre>
#       <id>T1105</id>
#     </mitre>
#   </rule>
# </group>
#
# Notes:
# - if_matched_sid chain (100101->100100, 100102->100101, etc.)
#   only works within same decoded event. Cross-event not supported.
# - 100104 uses frequency+timeframe: counts 100100 matches within 60s
# - Does NOT verify event order, just volume of /tmp events
# - For ordered chain detection: use Wazuh `context` or external SIEM

# Run 4 iterations of the chain within 60s to trigger frequency=4 on 100104
# Each iteration generates at minimum a /tmp create event (100100 match)

for i in 1 2 3 4; do
    TF="/tmp/.test_chain_${i}.sh"

    cat > "$TF" << 'SCRIPT'
#!/bin/bash
curl -s --connect-timeout 5 http://example.com > /dev/null 2>&1 || \
wget -q --timeout=5 http://example.com -O /dev/null 2>&1 || \
nc -z -w5 example.com 80 2>&1
SCRIPT

    chmod +x "$TF"
    echo "[*] Iteration $i: executing $TF"
    "$TF"
    rm -f "$TF"
    sleep 1
done

echo ""
echo "[*] Expected alerts per iteration:"
echo "    100100 - /tmp file create (x4 total)"
echo "    100101 - chmod +x (if merged with create in same event)"
echo "    100102 - execve/bash (per-event)"
echo "    100103 - outbound curl/wget/nc (per-event)"
echo ""
echo "[*] 100104 fires ONCE after 4th 100100 match within 60s"
echo "[*] Does NOT enforce ordered chain (create->chmod->exec->net)"
echo "[*] For ordered chain: use <context> grouping or external tool"
