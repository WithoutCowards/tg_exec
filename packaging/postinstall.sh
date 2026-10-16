#!/bin/sh
# Keep the config private: it may hold the bot token.
if [ -f /etc/tg-exec/config.conf ]; then
	chmod 600 /etc/tg-exec/config.conf 2>/dev/null || true
fi
if [ -f /etc/tg-exec/token.cred ]; then
	chmod 600 /etc/tg-exec/token.cred 2>/dev/null || true
fi
echo "tg-exec installed. Configure it with: sudo tg-exec --setup   (or edit /etc/tg-exec/config.conf)"
exit 0
