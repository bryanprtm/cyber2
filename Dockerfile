# Security Operation Center - Ubuntu 20.04 Container
# Repository: https://github.com/bryanprtm/cyber2.git

FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production
ENV PORT=5000

# Set working directory
WORKDIR /opt/security-operations-center

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    nodejs \
    npm \
    postgresql-client \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Clone the Security Operation Center repository
RUN git clone https://github.com/bryanprtm/cyber2.git .

# Install Node.js dependencies
RUN npm install --production

# Create necessary directories
RUN mkdir -p /var/log/supervisor /var/log/nginx

# Copy configuration files
COPY install-ubuntu20-container.sh /setup.sh
RUN chmod +x /setup.sh

# Create application user
RUN useradd -r -s /bin/false soc-user

# Set proper permissions
RUN chown -R soc-user:soc-user /opt/security-operations-center

# Expose port
EXPOSE 5000 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Start command
CMD ["npm", "run", "dev"]

# Metadata
LABEL maintainer="Security Operation Center Team"
LABEL version="2.0.0"
LABEL description="Advanced Cybersecurity Toolkit for Ethical Security Testing"
LABEL repository="https://github.com/bryanprtm/cyber2.git"