rule shadedetect
{
	strings:
		$a="lhttp://crl.usertrust.com/UTN-USERFirst-Object.cr105"
		$b="http://ocsp.usertrust.com"
		$c="The USERTRUST Networki!0"
		$d="http://www.usertrust.com1"
		$e="UTN-USERFirst-Object"
		$f="The USERTRUST Network1!0"
		$g="http://www.usertrust.com1"
		$h="UTN-USERFirst-Object0"
		$i="GetAsynckeyState" fullword ascii
	condition:
		$a or $b or $c or $d or $e or $f or $g or $h or și
}
