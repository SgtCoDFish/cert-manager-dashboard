#!/bin/sh

set -e

# Ensure systemd service is loaded
if command -v systemctl >/dev/null; then
	systemctl daemon-reload
fi

# Ensure cert-manager-dashboard user exists
if command -v systemd-sysusers >/dev/null; then
	systemd-sysusers
fi

# If we're configuring the .deb file, ensure that we enable the dashboard site configuration for nginx
case "$1" in
	configure)
		site=cert-manager-dashboard.conf
		AVAIL="/etc/nginx/sites-available/$site"
		ENABLED="/etc/nginx/sites-enabled/$site"

		if [ -f "$AVAIL" ]; then
			if [ ! -L "$ENABLED" ]; then
				ln -s "$AVAIL" "$ENABLED"
			fi
		else
			echo "Warning: site config $AVAIL not found" >&2
		fi

		# Test Nginx configuration before reload
		if nginx -t; then
			if command -v systemctl >/dev/null 2>&1; then
				systemctl reload nginx || true
			else
				service nginx reload || true
			fi
		else
			echo "Nginx configuration test failed, not reloading." >&2
		fi
	;;
esac
