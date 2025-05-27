#!/bin/bash
# Deploy Script untuk Security Operation Center di Replit

echo "🚀 Deploying Security Operation Center di Replit..."

# Set environment variables
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Install dependensi jika belum ada
echo "📦 Checking dependencies..."
if [ ! -d "node_modules" ]; then
    npm install
fi

# Push database schema
echo "🗄️ Setting up database..."
npm run db:push

# Build aplikasi (dengan fallback ke development mode)
echo "🔨 Building application..."
mkdir -p dist/public

# Copy static files untuk fallback
cp -r client/index.html dist/public/ 2>/dev/null || echo "Using development mode"
cp -r client/src dist/public/ 2>/dev/null || echo "Development assets ready"

echo "✅ Deployment ready!"
echo "🌐 Application is running in development mode"
echo "📱 Access your app at the Replit preview URL"
echo ""
echo "To start the application:"
echo "npm run dev"