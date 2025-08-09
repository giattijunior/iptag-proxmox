PREFIX       := /
SBIN_DIR     := /usr/local/bin
OPT_DIR      := /opt/iptag
SYSTEMD_DIR  := /etc/systemd/system
LOGROTATE_D  := /etc/logrotate.d

all: install

install:
	install -d $(OPT_DIR)
	[ -f $(OPT_DIR)/iptag.conf ] || install -m 0644 files/iptag.conf $(OPT_DIR)/iptag.conf
	install -m 0755 files/iptag $(OPT_DIR)/iptag
	install -m 0755 files/iptag-run $(SBIN_DIR)/iptag-run
	install -m 0755 files/iptag-mode $(SBIN_DIR)/iptag-mode
	install -m 0755 files/iptag-color $(SBIN_DIR)/iptag-color
	install -m 0644 files/iptag.service $(SYSTEMD_DIR)/iptag.service
	install -m 0644 files/iptag.timer   $(SYSTEMD_DIR)/iptag.timer
	install -m 0644 files/iptag.logrotate $(LOGROTATE_D)/iptag
	systemctl daemon-reload
	systemctl enable --now iptag.timer
	$(SBIN_DIR)/iptag-run || true
	@echo ">> IP-Tag instalado. Config: $(OPT_DIR)/iptag.conf  Log: /var/log/iptag.log"

update:
	$(MAKE) install

uninstall:
	-systemctl disable --now iptag.timer
	-rm -f $(SYSTEMD_DIR)/iptag.timer $(SYSTEMD_DIR)/iptag.service
	-systemctl daemon-reload
	-rm -f $(LOGROTATE_D)/iptag
	-rm -f $(SBIN_DIR)/iptag-run $(SBIN_DIR)/iptag-mode $(SBIN_DIR)/iptag-color
	-rm -rf $(OPT_DIR)
	@echo ">> IP-Tag removido."
