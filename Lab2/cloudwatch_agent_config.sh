#!/bin/bash
#sudo yum install -y amazon-cloudwatch-agent
# ===== CloudWatch Agent bootstrap (future-proof) =====
set -e
# Install CloudWatch Agent
if command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y amazon-cloudwatch-agent
else
  sudo yum install -y amazon-cloudwatch-agent
fi

# Ensure dirs exist
sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.d

# Writing config to a specific path
#cat <<'EOT' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null

# Write JSON config (NO empty file risk)
sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null <<'EOT'
{
  "agent": { "region": "us-east-1" },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/cloudwatch-init-output.log",
            "log_group_name": "/aws/ec2/megatron-userdata",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
            "log_group_name": "/aws/ec2/megatron-cwagent",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOT

# FIX: Point -c to the file path used above (/etc/amazon-cloudwatch-agent.json)
#sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
# Validate JSON (prevents crash-loop)
python3 -m json.tool /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null \
  || { echo "CloudWatch JSON invalid"; cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json; exit 1; }

# Clean old configs
sudo systemctl stop amazon-cloudwatch-agent || true
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.d/* || true

# Load config + start agent
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
-a fetch-config -m ec2 \
-c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
-s
# These are technically redundant if you use the '-s' flag above, but safe to keep
sudo systemctl enable amazon-cloudwatch-agent
sudo systemctl start amazon-cloudwatch-agent
