#!/bin/bash

# GhostBuster API Configuration Setup Script
# Interactive setup for Shodan, HIBP, and other APIs

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  GhostBuster API Setup                        ║"
echo "║            Configure Shodan, HIBP & Phone APIs                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

CONFIG_FILE="config.yaml"

# Check if config.yaml already exists
if [ -f "$CONFIG_FILE" ]; then
    echo "⚠️  config.yaml already exists!"
    read -p "Do you want to update it? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting without changes."
        exit 0
    fi
fi

# Initialize config file with defaults if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    cp config.example.yaml "$CONFIG_FILE"
    echo "✓ Created config.yaml from example"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "PART 1: CORE APIs (Recommended) 🔑"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Shodan Setup
echo "📊 SHODAN - Infrastructure Scanning"
echo "   Get key at: https://account.shodan.io/"
echo ""
read -p "Enter your Shodan API key (or press Enter to skip): " shodan_key

if [ -n "$shodan_key" ]; then
    sed -i "s/shodan_key: \"\"/shodan_key: \"$shodan_key\"/" "$CONFIG_FILE"
    echo "✓ Shodan key configured"
fi

echo ""

# HIBP Setup
echo "🔓 Have I Been Pwned - Email Breach Checking"
echo "   Get key at: https://haveibeenpwned.com/API/Key"
echo ""
read -p "Enter your HIBP API key (or press Enter to skip): " hibp_key

if [ -n "$hibp_key" ]; then
    sed -i "s/hibp_key: \"\"/hibp_key: \"$hibp_key\"/" "$CONFIG_FILE"
    echo "✓ HIBP key configured"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "PART 2: PHONE Intelligence (Optional) 📱"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "For best results, add 2-3 phone providers (all have free tiers):"
echo ""

# Phone APIs
phone_apis=(
    "numverify_key|NumVerify|https://numverify.com/|100/month"
    "veriphone_key|VeriPhone|https://veriphone.io/|1000/month"
    "abstractapi_key|AbstractAPI|https://app.abstractapi.com/|100/month"
    "ipqs_key|IPQS|https://ipqualityscore.com/|200/month"
)

for api_config in "${phone_apis[@]}"; do
    IFS='|' read -r var_name api_name api_url api_free <<< "$api_config"

    echo "📱 $api_name"
    echo "   Get key at: $api_url"
    echo "   Free tier: $api_free"
    read -p "   Enter API key (or press Enter to skip): " api_key

    if [ -n "$api_key" ]; then
        sed -i "s/${var_name}: \"\"/${var_name}: \"$api_key\"/" "$CONFIG_FILE"
        echo "   ✓ $api_name configured"
    fi
    echo ""
done

echo "═══════════════════════════════════════════════════════════════"
echo "Setup Complete! ✅"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Your configuration is saved in: $CONFIG_FILE"
echo ""
echo "Test your setup:"
echo "  📧 Email:     python3 ghostbuster.py admin@example.com -c $CONFIG_FILE"
echo "  🌍 IP:        python3 ghostbuster.py 8.8.8.8 -c $CONFIG_FILE"
echo "  📱 Phone:     python3 ghostbuster.py +919876543210 -c $CONFIG_FILE"
echo ""
echo "For more help, read: API_SETUP_GUIDE.md"
echo ""
