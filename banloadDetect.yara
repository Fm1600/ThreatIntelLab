rule banloadDetect
{
	strings:
		$a="http://th.symcb.com/th.crl0" nocase
		$b="http://th.symcd.com0&"	nocase
		$c="http://th.symcb.com/th.crt0" nocase
		$d="ykernel32.exe"	nocase
		$e="74c72d885e167c1ce277d33f8d8798f72c9c1c4c"
		$f="F:\Sistema\Drivers-Denis\FileDelete\FileDelete\Debug\B.pdb"
	condition:
		$a or $b or $c or $d or $e or $f
}
