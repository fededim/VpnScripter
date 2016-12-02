# VpnScripter © 2016 Federico Di Marco

A scripter for Windows VPN connections. 

## Description

This is a general PowerShell script which creates automatically a set of VPN connections according to a XML configuration file called vpnconfig.xml. This file defines a set of vpn providers (Provider element node) and for each provider specifies a set of servers (Server sub element node) for each of which a vpn connection will be created in Windows. Let's examine the nodes:

- Provider: this node corresponds to a vpn provider. Attributes:
	- name: used to generate the vpn connection name in Windows.
	- basedomain: used to generate host name of the vpn server (usually a vpn provider offers a set of servers which share a common domain name). It can be overridden in server node.
	- l2tppsk: it's the pre-shared secret for L2TP/IPSEC connection (usually it is the same for all server of the same provider).
	- user: it's the username to access the vpn (again it should be the same across all servers).
	- password: it's the password associated to the previous username (again it should be the same across all servers).
	- proto: specifies the vpn protocol to use for all servers, if left empty it means automatic.
- Server: this node corresponds to a server of a vpn provider. Attributes:
	- server: specifies the host name of the server. If this attribute does not contain the "." character the host name is obtained by concatenating this field to provider's base domain, otherwise host name is equal to this field.
	- proto: specifies the vpn protocol to use. It also overrides any protocol defined in provider node.

Inside the repository you will find a solution made up of 3 files:

- DotRas.dll: it's a .NET class library which is used by the PowerShell script to create VPN connections and it must be in the same folder of the script.
- vpnconfig.xml: it's the above xml configuration file which must be edited with your settings.
- VpnScripter.ps1: it is a PowerShell script which can be launched from Powershell or double clicked. It accepts an optional parameter named ConfigFile specifying the name of the xml configuration file to use (defaults to vpnconfig.xml). You can specify the -Debug flag to obtain a more verbose log output.

The script has been tested on Windows 10, but should also work in any Windows with at least PowerShell 3.0.

## License

See [LICENSE](LICENSE) file.

Please see [VpnScripter](https://www.codeproject.com/Articles/1158881/VPNScripter-a-scripter-for-Windows-VPN-connections) for more information.