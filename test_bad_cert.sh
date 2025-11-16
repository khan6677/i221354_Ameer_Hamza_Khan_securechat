#!/bin/bash
# Test 2: BAD_CERT - Invalid Certificate Test
# This script tests that the server rejects invalid certificates

echo "🧪 Test 2: BAD_CERT - Invalid Certificate Test"
echo "=============================================="
echo ""

# Backup original client certificate
echo "📦 Backing up original client certificate..."
cp certs/client.crt certs/client.crt.backup
cp certs/client.key certs/client.key.backup

# Generate self-signed certificate (not signed by CA)
echo "🔨 Generating self-signed certificate (not signed by CA)..."
openssl req -x509 -newkey rsa:2048 -keyout certs/client.key \
    -out certs/client.crt -days 365 -nodes \
    -subj "/CN=fake.local/O=FAKE/C=XX" 2>/dev/null

echo ""
echo "✅ Self-signed certificate created"
echo ""
echo "📝 Now run the client in another terminal:"
echo "   python -m app.client"
echo ""
echo "Expected result: Server should reject with 'BAD_CERT' error"
echo ""
echo "Press Enter when done to restore original certificate..."
read

# Restore original certificate
echo "♻️  Restoring original client certificate..."
mv certs/client.crt.backup certs/client.crt
mv certs/client.key.backup certs/client.key

echo "✅ Original certificate restored"
echo ""
echo "Test complete! Check server output for BAD_CERT error."

