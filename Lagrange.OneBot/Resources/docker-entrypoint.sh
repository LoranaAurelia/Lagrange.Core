#!/bin/sh

# If LAGRANGE_WORKDIR is set, use it; otherwise stay in current directory
if [ -n "$LAGRANGE_WORKDIR" ]; then
    mkdir -p "$LAGRANGE_WORKDIR"
    cd "$LAGRANGE_WORKDIR"
fi

exec /app/bin/Lagrange.OneBot "$@"
