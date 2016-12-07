# Vpn Scripter © 2016 Federico Di Marco
param([string]$ConfigFile = "vpnconfig.xml")

#simple xsd schema
$xsd=@"
<?xml version="1.0" encoding="utf-8"?>
<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" xmlns:xs="http://www.w3.org/2001/XMLSchema">
 <xs:simpleType name="NotEmptyTrimmedString">
    <xs:restriction base="xs:string">
      <xs:pattern value="^\S(.*\S)?$" />
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Providers">
    <xs:complexType>
      <xs:sequence>
        <xs:element maxOccurs="unbounded" name="Provider">
          <xs:complexType>
            <xs:sequence>
              <xs:element maxOccurs="unbounded" name="Server">
                <xs:complexType>
                  <xs:attribute name="server" type="NotEmptyTrimmedString" use="required" />
                  <xs:attribute name="proto" type="xs:string" use="optional" />
				  <xs:attribute name="l2tppsk" type="xs:string" use="optional" />
				  <xs:attribute name="user" type="xs:string" use="optional" />
				  <xs:attribute name="password" type="xs:string" use="optional" />
                </xs:complexType>
              </xs:element>
            </xs:sequence>
            <xs:attribute name="name" type="NotEmptyTrimmedString" use="required" />
            <xs:attribute name="basedomain" type="xs:string" use="optional" />
            <xs:attribute name="l2tppsk" type="xs:string" use="optional" />
            <xs:attribute name="user" type="xs:string" use="optional" />
            <xs:attribute name="password" type="xs:string" use="optional" />
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
"@

# C# helper code to create VPN with DotRas library
$Source = @"
	using DotRas; 
	using System; 
	using System.Xml;
	using System.Xml.Schema;
	using System.IO;

	public class VpnHelper {

		public static XmlSchema GetXsdSchema(string schema) {
			return XmlSchema.Read(new StringReader(schema), (e,args) => Console.WriteLine("XML schema error: "+args));	
		}


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

Add-Type -Path $psscriptroot\DotRas.dll
Add-Type -AssemblyName System.Xml
Add-Type -ReferencedAssemblies $psscriptroot\DotRas.dll,System.Xml -TypeDefinition $Source -Language CSharp  


# String coalescing helper function not available in Powershell
function Coalesce([string[]] $StringsToLookThrough, [switch]$EmptyStringAsNull) {
  if ($EmptyStringAsNull.IsPresent) {
    return ($StringsToLookThrough | Where-Object { $_ } | Select-Object -first 1)
  }
  else {
    return (($StringsToLookThrough -ne $null) | Select-Object -first 1)
  }  
}


function ValidateLoadXml([string] $XmlFile, [string] $Schema) {

	$verr={ 
		Write-Error "Error: malformed XSD/XML Line: $($_.Exception.LineNumber) Offset: $($_.Exception.LinePosition) - $($_.Message)" 
		throw [System.IO.InvalidDataException] 
	}

	try {
		[System.Xml.XmlReaderSettings]$readsett=New-Object System.Xml.XmlReaderSettings
		$readsett.Schemas.Add([System.Xml.Schema.XmlSchema]::Read((New-Object System.IO.StringReader($Schema)),$verr))
		$readsett.ValidationType=[System.Xml.ValidationType]::Schema
		$readsett.add_ValidationEventHandler($verr)
		$xmlconf = New-Object System.Xml.XmlDocument
		$xmlconf.Load([System.Xml.XmlReader]::Create($XmlFile,$readsett))
	}
	catch [System.IO.InvalidDataException]  {
		return $null
	}
	
	return $xmlconf
}


Write-Host "`nVPN CREATION SCRIPT © 2016 Federico Di Marco"
Write-Host "---------------------------------------------`n`n"


$pbkfile="$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk"
$cfgfile=Resolve-Path $ConfigFile # Visual studio Powershell debug project uses IDE folder as working path...still to figure how to switch to $(SolutionDir)

Write-Host "Info: Dll location $psscriptroot\DotRas.dll"
Write-Host "Info: Configuration file $cfgfile"
Write-Host "Info: Phonebook file $pbkfile`n"

$xmlconf=ValidateLoadXml $cfgfile $xsd # do not use comma to separate parameters otherwise the 2 strings get concatenated
if ($xmlconf -ne $null) {
	ForEach ($provider in $xmlconf.Providers.Provider) {
		Write-Debug "Debug: Provider $($provider.name)"

		ForEach ($server in $($provider.Server)) {
			Write-Host "`n"

			Write-Debug "Debug: Server $($server.server)"
			$temp=$server.server.Split('.')

			Write-Debug "Debug: Server $($server.server) Splitted $temp Count $($temp.Count)"
			if ($temp.Count -eq 1) {
				$serverurl="$($server.server).$($provider.basedomain)"
			}
			else {
				$serverurl=$server.server
			}


			$proto=(Coalesce $server.proto,$provider.proto -EmptyStringAsNull)
			$l2tppsk=(Coalesce $server.l2tppsk,$provider.l2tppsk -EmptyStringAsNull)
			$user=(Coalesce $server.user,$provider.user -EmptyStringAsNull)
			$password=(Coalesce $server.password,$provider.password -EmptyStringAsNull)

			# Parameters validation
			if ([string]::IsNullOrWhitespace($user) -Or [string]::IsNullOrWhitespace($password)) {
				Write-Warning "Error: Provider $($provider.name) Server $($server.server) either user or password field is empty, skipping.`n"
				continue;
			}

			if ([string]::Equals($proto, "L2TP", [StringComparison]::OrdinalIgnoreCase) -And [string]::IsNullOrWhitespace($l2tppsk)) {
				Write-Warning "Error: Provider $($provider.name) Server $($server.server) L2TP/IPSEC proto selected and l2tppsk field is empty, skipping.`n"
				continue;
			}


			$vpnname = if (($proto) -and ($proto -ne "Auto")) { "$($temp[0].ToUpper()) $proto $($provider.name)" } else { "$($temp[0].ToUpper()) $($provider.name)" }
				
			$exist=Get-VpnConnection -Name $vpnname -ErrorAction silentlycontinue
			if ($exist -ne $null) {
				Write-Host "Info: Removing VPN connection $vpnname"
		
				Remove-VpnConnection -Name $vpnname -Force	
			}

			Write-Host "Info: Adding VPN connection Name $vpnname Server $serverurl Protocol Proto $(Coalesce $proto,""Auto"")"
			[VpnHelper]::Add($pbkfile,$vpnname,$serverurl,$proto,$l2tppsk,$user,$password)

		
			# I tried first with standard powershell function Add-VpnConnection yet I was unable to find a way to pass credentials while creating the vpn
			# I gave up after having tried everything and I switched to DotRas library. If someone know how to pass them please let me know.
			#$a = New-EapConfiguration
			#$a | Get-Member
			#$a
			#$a.EapConfigXmlStream
			#$a.EapConfigXmlStream.EapHostConfig.Config.Eap
			#$a.EapConfigXmlStream.EapHostConfig.Config.Eap.EapType
			#Add-VpnConnection -Name $vpnname -ServerAddress $serverurl -TunnelType $proto -EncryptionLevel Maximum -AuthenticationMethod Eap -AllUserConnection -L2tpPsk $provider.l2tppsk -Force -RememberCredential
		}	

	}
}
Write-Host -NoNewLine "`nPress any key to continue . . . "
[Console]::ReadKey($true) | Out-Null
