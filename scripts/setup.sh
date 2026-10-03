#!/bin/bash

# MySocial Salt Service Setup Script

set -e

echo "🚀 MySocial Salt Service Setup"
echo "========================"

# Check database URL
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL environment variable not set"
    exit 1
fi

echo "✅ Environment variables configured"

# Run migrations
echo ""
echo "🗄️  Running database migrations..."
sqlx migrate run

echo "✅ Migrations completed"

# Build the project
echo ""
echo "🔨 Building project..."
cargo build --release

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the service:"
echo "  cargo run --release"
echo ""
echo "Or for production:"
echo "  ./target/release/myso-salt-service" 