using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Conexoes.Core.Models;
using Microsoft.Win32.SafeHandles;

namespace Conexoes.Core.Security;

/// <summary>
/// Verifica assinatura Authenticode de executáveis (embutida ou via catálogo do Windows,
/// usado pela maioria dos binários do sistema). Resultados ficam em cache por caminho e data.
/// </summary>
public static class SignatureVerifier
{
    private static readonly ConcurrentDictionary<(string Path, DateTime Write), SignatureInfo> Cache = new();

    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;

    public static SignatureInfo Verify(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return SignatureInfo.Unknown;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return SignatureInfo.Unknown;
            return Cache.GetOrAdd((fi.FullName.ToLowerInvariant(), fi.LastWriteTimeUtc), _ => VerifyUncached(fi.FullName));
        }
        catch
        {
            return SignatureInfo.Unknown;
        }
    }

    private static SignatureInfo VerifyUncached(string path)
    {
        var embedded = VerifyEmbedded(path);
        if (embedded == 0)
            return new SignatureInfo(SignatureStatus.Valida, GetPublisher(path));

        if (embedded is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
        {
            var (catResult, catalogPath) = VerifyCatalog(path);
            if (catalogPath is not null)
                return new SignatureInfo(MapFailure(catResult), GetPublisher(catalogPath) ?? "Catálogo do Windows");

            return VerifyPackage(path) ?? new SignatureInfo(SignatureStatus.NaoAssinado, null);
        }

        return new SignatureInfo(MapFailure(embedded), GetPublisher(path));
    }

    private static SignatureStatus MapFailure(uint result) => result switch
    {
        0 => SignatureStatus.Valida,
        CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CERT_E_UNTRUSTEDTESTROOT => SignatureStatus.NaoConfiavel,
        _ => SignatureStatus.Invalida,
    };

    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_CHAINING = 0x800B010A;
    private const uint CERT_E_UNTRUSTEDTESTROOT = 0x800B010D;

    /// <summary>
    /// Apps MSIX/Microsoft Store: os arquivos não têm assinatura própria; o pacote inteiro é assinado
    /// (AppxSignature.p7x) e validado pelo Windows na instalação. A pasta WindowsApps só é gravável pelo sistema.
    /// </summary>
    private static SignatureInfo? VerifyPackage(string path)
    {
        const string marker = @"\WindowsApps\";
        var idx = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var rest = path[(idx + marker.Length)..];
        var slash = rest.IndexOf('\\');
        if (slash <= 0) return null;
        var root = Path.Combine(path[..(idx + marker.Length)], rest[..slash]);
        if (!File.Exists(Path.Combine(root, "AppxSignature.p7x"))) return null;

        string? publisher = null;
        try
        {
            var manifest = System.Xml.Linq.XDocument.Load(Path.Combine(root, "AppxManifest.xml"));
            var identity = manifest.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "Identity");
            var dn = identity?.Attribute("Publisher")?.Value;
            if (dn is not null)
            {
                var cn = dn.Split(',').Select(p => p.Trim()).FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
                publisher = (cn?[3..] ?? dn).Trim('"');
            }
        }
        catch
        {
            // manifesto ilegível: segue sem publicador
        }
        return new SignatureInfo(SignatureStatus.Valida, (publisher ?? "Pacote MSIX") + " (pacote MSIX)");
    }

    private static string? GetPublisher(string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
        }
        catch
        {
            return null;
        }
    }

    private static uint VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            return RunWinVerifyTrust(WTD_CHOICE_FILE, pFile);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static (uint Result, string? CatalogPath) VerifyCatalog(string path)
    {
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var hCatAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
                continue;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref hashSize, null, 0);
                if (hashSize == 0) continue;
                var hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref hashSize, hash, 0))
                    continue;

                var hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
                if (hCatInfo == IntPtr.Zero) continue;
                try
                {
                    var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) continue;

                    var catalogInfo = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                        pcwszCatalogFilePath = catInfo.wszCatalogFile,
                        pcwszMemberTag = Convert.ToHexString(hash),
                        pcwszMemberFilePath = path,
                        hCatAdmin = hCatAdmin,
                    };
                    var pHash = Marshal.AllocHGlobal(hash.Length);
                    var pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                    try
                    {
                        Marshal.Copy(hash, 0, pHash, hash.Length);
                        catalogInfo.pbCalculatedFileHash = pHash;
                        catalogInfo.cbCalculatedFileHash = hashSize;
                        Marshal.StructureToPtr(catalogInfo, pCat, false);
                        return (RunWinVerifyTrust(WTD_CHOICE_CATALOG, pCat), catInfo.wszCatalogFile);
                    }
                    finally
                    {
                        Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
                        Marshal.FreeHGlobal(pCat);
                        Marshal.FreeHGlobal(pHash);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
            catch (IOException)
            {
                return (TRUST_E_NOSIGNATURE, null);
            }
            catch (UnauthorizedAccessException)
            {
                return (TRUST_E_NOSIGNATURE, null);
            }
            finally
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
        return (TRUST_E_NOSIGNATURE, null);
    }

    private static uint RunWinVerifyTrust(uint unionChoice, IntPtr pUnion)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = pUnion,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        };
        var action = WintrustActionGenericVerifyV2;
        var pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(data, pData, false);
            var result = WinVerifyTrust(new IntPtr(-1), ref action, pData);
            data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, true);
            WinVerifyTrust(new IntPtr(-1), ref action, pData);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(pData);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
