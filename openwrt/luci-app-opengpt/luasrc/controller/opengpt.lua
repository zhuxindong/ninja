local sys  = require "luci.sys"
local http = require "luci.http"

module("luci.controller.opengpt", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/opengpt") then
		return
	end

	local page
	page = entry({ "admin", "services", "opengpt" }, alias("admin", "services", "opengpt", "client"), _("OpenGPT"), 10)
	page.dependent = true
	page.acl_depends = { "luci-app-opengpt" }

	entry({ "admin", "services", "opengpt", "client" }, cbi("opengpt/client"), _("Settings"), 10).leaf = true
	entry({ "admin", "services", "opengpt", "log" }, form("opengpt/log"), _("Log"), 30).leaf = true
	
	entry({"admin", "services", "opengpt", "status"}, call("act_status")).leaf = true
	entry({ "admin", "services", "opengpt", "logtail" }, call("action_logtail")).leaf = true
end

function act_status()
	local e = {}
	e.running = sys.call("pgrep -f opengpt >/dev/null") == 0
	e.application = luci.sys.exec("opengpt --version")
	http.prepare_content("application/json")
	http.write_json(e)
end

function action_logtail()
	local fs = require "nixio.fs"
	local log_path = "/var/log/opengpt.log"
	local e = {}
	e.running = luci.sys.call("pidof opengpt >/dev/null") == 0
	if fs.access(log_path) then
		e.log = luci.sys.exec("tail -n 200 %s | sed 's/\\x1b\\[[0-9;]*m//g'" % log_path)
	else
		e.log = ""
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end