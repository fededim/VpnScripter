# Vpn Scripter © 2016 Federico Di Marco
param([string]$ConfigFile = "vpnconfig.xml")

# String coalescing helper function not available in Powershell
function Coalesce([string[]] $StringsToLookThrough, [switch]$EmptyStringAsNull) {
  if ($EmptyStringAsNull.IsPresent) {
    return ($StringsToLookThrough | Where-Object { $_ } | Select-Object -first 1)
  } else {
    return (($StringsToLookThrough -ne $null) | Select-Object -first 1)
  }  
}


# C# helper code to create VPN with DotRas library
$Source = @"
	using DotRas; 
	using System; 

	public class VpnHelper {

	
		static RasVpnStrategy ConvertProto(String proto) {
			if (String.IsNullOrEmpty(proto))
				return DotRas.RasVpnStrategy.Default;
			else if (String.Equals(proto, "L2TP", StringComparison.OrdinalIgnoreCase))
				return DotRas.RasVpnStrategy.L2tpOnly;
			else if (String.Equals(proto, "SSTP", StringComparison.OrdinalIgnoreCase))
				return DotRas.RasVpnStrategy.SstpOnly;
			else if (String.Equals(proto, "IKEV2", StringComparison.OrdinalIgnoreCase))
				return DotRas.RasVpnStrategy.IkeV2Only;
			else if (String.Equals(proto, "PPTP", StringComparison.OrdinalIgnoreCase))
				return DotRas.RasVpnStrategy.PptpOnly;
		
			return DotRas.RasVpnStrategy.Default;
		}
	
	
		public static void Add(string path,string name,string server, string proto, string l2tppsk, string user, string password) {
			RasPhoneBook PhoneBook=new RasPhoneBook();

            PhoneBook.Open(path);

            RasEntry VpnEntry = RasEntry.CreateVpnEntry(name,server, ConvertProto(proto), RasDevice.Create(name, DotRas.RasDeviceType.Vpn), true);
            VpnEntry.Options.UsePreSharedKey = true;
            VpnEntry.Options.CacheCredentials = true;
            VpnEntry.Options.ReconnectIfDropped = true;
			if (VpnEntry.VpnStrategy==RasVpnStrategy.IkeV2Only) {
				// 23 EAP-AKA
				// 50 EAP-AKA'
				// 18 EAP-SIM
				// 21 EAP-TTLS
				// 25 PEAP
				// 26 EAP-MSCHAPV2
				// 13 EAP-smart card or certificate
				VpnEntry.Options.RequireEap = true;
				VpnEntry.CustomAuthKey=26; // 26 means eap-mschapv2 username/password
			}
			else { 
				VpnEntry.Options.RequireMSChap2 = true;				
            }

            //VpnEntry.Options.RequireWin95MSChap = false; // seems to be ignored, chap is still checked in newly created vpn profile
            //VpnEntry.Options.RequireMSChap = false;  // seems to be ignored, chap is still checked in newly created vpn profile
            //VpnEntry.Options.RequireChap = false; // seems to be ignored, chap is still checked in newly created vpn profile
            VpnEntry.EncryptionType = RasEncryptionType.RequireMax;
            PhoneBook.Entries.Add(VpnEntry);
            VpnEntry.UpdateCredentials(RasPreSharedKey.Client,l2tppsk);
            VpnEntry.UpdateCredentials(new System.Net.NetworkCredential(user,password));
		}		
	}
"@

# Small 
Add-Type -Path $psscriptroot\DotRas.dll
Add-Type -ReferencedAssemblies $psscriptroot\DotRas.dll -TypeDefinition $Source -Language CSharp  

Write-Host "`nVPN CREATION SCRIPT © 2016 Federico Di Marco"
Write-Host "---------------------------------------------`n`n"


$pbkfile="$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk"

Get-Location
#Set-Location $psscriptroot

Write-Host "Dll location $psscriptroot\DotRas.dll"
Write-Host "Configuration file $ConfigFile"
Write-Host "Phonebook file $pbkfile`n"

[xml]$xmlconf = Get-Content $ConfigFile

ForEach ($provider in $xmlconf.Providers.Provider) {
	Write-Debug "Debug: Provider $($provider.name)"
	ForEach ($server in $($provider.Server)) {
		Write-Debug "Debug: Server $($server.server)"
		$temp=$server.server.Split('.')

		#$temp| Get-Member

		Write-Debug "Debug: Server $($server.server) Splitted $temp Count $($temp.Count)"
		if ($temp.Count -eq 1) {
			$serverurl="$($server.server).$($provider.basedomain)"
		}
		else {
			$serverurl=$server.server
		}


		$proto=(Coalesce $server.proto,$provider.proto -EmptyStringAsNull)
		$vpnname = if (($proto) -and ($proto -ne "Auto")) { "$($temp[0].ToUpper()) $proto $($provider.name)" } else { "$($temp[0].ToUpper()) $($provider.name)" }
				
		$exist=Get-VpnConnection -Name $vpnname -ErrorAction silentlycontinue
		if ($exist -ne $null) {
			Write-Host "Info: Removing VPN connection $vpnname"
		
			Remove-VpnConnection -Name $vpnname -Force	
		}

		Write-Host "Info: Adding VPN connection Name $vpnname Server $serverurl Protocol Proto $(Coalesce $proto,""Auto"")`n"
		[VpnHelper]::Add($pbkfile,$vpnname,$serverurl,$proto,$provider.l2tppsk,$provider.user,$provider.password)

		
		# I tried first with standard powershell function Add-VpnConnection yet I was unable to find a way to pass credentials while creating the vpn
		# I gave up after having tried everything and I switched to DotRas library. If someone know how to create them please let me know.
		#$a = New-EapConfiguration
		#$a | Get-Member
		#$a
		#$a.EapConfigXmlStream
		#$a.EapConfigXmlStream.EapHostConfig.Config.Eap
		#$a.EapConfigXmlStream.EapHostConfig.Config.Eap.EapType
		#Add-VpnConnection -Name $vpnname -ServerAddress $serverurl -TunnelType $proto -EncryptionLevel Maximum -AuthenticationMethod Eap -AllUserConnection -L2tpPsk $provider.l2tppsk -Force -RememberCredential
	}	

}

Write-Host -NoNewLine "`nPress any key to continue . . . "
[Console]::ReadKey($true) | Out-Null
