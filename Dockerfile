# Stage 1: Build Environment
FROM node:20-bookworm AS builder

# Install dependencies required by electron and electron-builder
RUN apt-get update && apt-get install -y \
    libnss3 \
    libatk1.0-0 \
    libasound2 \
    libgbm1 \
    libdrm2 \
    libxshmfence1 \
    libx11-xcb1 \
    libxcb-dri3-0 \
    libxtst6 \
    libxss1 \
    libgtk-3-0 \
    build-essential \
    fakeroot \
    dpkg \
    rpm \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY electron-app/package*.json ./electron-app/

# Install dependencies
WORKDIR /app/electron-app
RUN npm ci

# Copy the rest of the application
WORKDIR /app
COPY . .

# Build the Linux directory version (unpacked)
WORKDIR /app/electron-app
RUN npm run build:dir:linux

# Stage 2: Runtime Environment
FROM node:20-bookworm-slim

# Install runtime dependencies for Electron to run under X11/headless
RUN apt-get update && apt-get install -y \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libasound2 \
    libgbm1 \
    libdrm2 \
    libxshmfence1 \
    libx11-xcb1 \
    libxcb-dri3-0 \
    libxtst6 \
    libxss1 \
    libgtk-3-0 \
    xvfb \
    x11-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the unpacked built application from the builder stage
COPY --from=builder /app/electron-app/dist/linux-unpacked /app/linux-unpacked

# Create a non-root user (Electron strongly discourages running as root without --no-sandbox)
RUN useradd -m kryptonuser && \
    chown -R kryptonuser:kryptonuser /app
USER kryptonuser

# Set environment variables for UI
ENV DISPLAY=:99
ENV NODE_ENV=production

# The application can be run headless via Xvfb for tests or directly for X11
# For direct X11, the user should map their DISPLAY environment variable
CMD ["/app/linux-unpacked/kryptonbrowser", "--no-sandbox"]
