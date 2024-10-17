1. Add a custom rule in /var/ossec/ruleset/rules/ (local_rules.xml) and restart Wazuh to load the new rules:
``` 
sudo systemctl restart wazuh-manager
```

2. Download script (file-check-and-delete.sh) at required directory and make script executable:
```
sudo chmod +x /var/ossec/active-response/bin/file-check-and-delete.sh
```
3. In /var/ossec/etc/ossec.conf, add the corresponding Active Response configuration and restart the Wazuh manager to apply the changes:
```
sudo systemctl restart wazuh-manager
```
4. Obtain API Keys and Configure Access (in this case VirusTotal and ANY.RUN):
   a. Create profile
   b. Go to profile and generate key
5. Test the integration
