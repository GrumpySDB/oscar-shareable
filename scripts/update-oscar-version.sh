#!/bin/bash

# Find the latest OSCAR version from the official website
LATEST_VERSION=$(curl -s https://www.sleepfiles.com/OSCAR/ | grep -o 'OSCAR [0-9]\+\.[0-9]\+\.[0-9]\+' | head -n 1 | awk '{print $2}')

if [ -z "$LATEST_VERSION" ]; then
    echo "Error: Could not determine latest OSCAR version."
    exit 1
fi

echo "Latest OSCAR version found: $LATEST_VERSION"

# Update .env file
if grep -q "OSCAR_VERSION=" .env; then
    sed -i "s/OSCAR_VERSION=.*/OSCAR_VERSION=$LATEST_VERSION/" .env
else
    echo "OSCAR_VERSION=$LATEST_VERSION" >> .env
fi

echo ".env file updated with OSCAR_VERSION=$LATEST_VERSION"
