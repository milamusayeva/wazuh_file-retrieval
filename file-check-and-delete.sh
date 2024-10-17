#!/bin/bash

ALERT_FILE=$1
VIRUSTOTAL_API_KEY="your_virustotal_api_key"
ANYRUN_API_KEY="your_anyrun_api_key"
ANYRUN_URL="https://api.any.run/v1/tasks"
VIRUSTOTAL_URL="https://www.virustotal.com/api/v3/files"
TEMP_DIR="/tmp/malware_files"

# Ensure temp directory exists
mkdir -p $TEMP_DIR

# Extract file path from Wazuh alert JSON
FILE_PATH=$(jq -r '.data.path' "$ALERT_FILE")

# Verify if the file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "[-] File not found: $FILE_PATH"
    exit 1
fi

echo "[+] File found: $FILE_PATH. Calculating hash..."

# Calculate SHA-256 hash of the file
FILE_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')

# Query VirusTotal for the hash
echo "[+] Checking VirusTotal for hash: $FILE_HASH"

VT_RESPONSE=$(curl -s -X GET "$VIRUSTOTAL_URL/$FILE_HASH" \
    -H "x-apikey: $VIRUSTOTAL_API_KEY")

VT_MALICIOUS=$(echo "$VT_RESPONSE" | jq '.data.attributes.last_analysis_stats.malicious')

if [ "$VT_MALICIOUS" -gt 0 ]; then
    echo "[!] File is flagged as malicious by VirusTotal. Uploading to ANY.RUN..."

    # Upload the file to ANY.RUN
    curl -X POST "$ANYRUN_URL" \
        -H "Authorization: Bearer $ANYRUN_API_KEY" \
        -F "task_type=analysis" \
        -F "file=@$FILE_PATH" -o "$TEMP_DIR/anyrun_response.json"

    # Wait for ANY.RUN results (you may need to poll the status in production)
    echo "[+] Uploaded to ANY.RUN. Waiting for analysis results..."

    sleep 60  # Adjust this sleep time as needed

    # Check ANY.RUN response for dangerous behavior (mocked check)
    ANYRUN_RESULT=$(jq -r '.data.status' "$TEMP_DIR/anyrun_response.json")

    if [[ "$ANYRUN_RESULT" == "malicious" ]]; then
        echo "[!] ANY.RUN confirmed malicious behavior. Deleting file: $FILE_PATH"
        rm -f "$FILE_PATH"
    else
        echo "[+] ANY.RUN analysis did not flag the file as malicious."
    fi
else
    echo "[+] File is not flagged as malicious by VirusTotal. No further action needed."
fi
