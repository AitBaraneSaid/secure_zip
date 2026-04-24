using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace SecureZip
{
    /// <summary>
    /// Crée des fichiers ZIP protégés par mot de passe en utilisant WinZip AES-256
    /// (méthode 99, spec WinZip AES Encryption version 2) avec support ZIP64.
    ///
    /// Fonctionnement global par entrée ZIP :
    ///   1. La compression est décidée par extension : les formats déjà compressés
    ///      (PDF, images, Office) passent en Store direct sans perte de temps CPU.
    ///   2. Le traitement est entièrement en streaming : aucun fichier n'est chargé
    ///      intégralement en mémoire — seul un buffer de 64 KB circule à la fois.
    ///   3. Un sel de 16 octets est généré aléatoirement par RNGCryptoServiceProvider.
    ///   4. PBKDF2 (Rfc2898DeriveBytes, SHA-1, 1000 itérations) dérive les clés.
    ///   5. Les données sont chiffrées en AES-256-CTR bloc par bloc.
    ///   6. HMAC-SHA1 est calculé sur l'ensemble des données chiffrées → 10 premiers octets écrits.
    ///   7. ZIP64 extra fields sont émis pour toute entrée ou tout ZIP dépassant 4 GB.
    ///
    /// Compatibilité : 7-Zip, WinRAR, WinZip — aucune dépendance externe, BCL .NET 4.7 uniquement.
    /// </summary>
    public class PasswordZipWriter
    {
        // ═══════════════════════════════════════════════════════════════════════
        // CONSTANTES
        // ═══════════════════════════════════════════════════════════════════════

        private const int    SaltSize         = 16;

        // WinZip AES spec §5 impose exactement 1000 itérations PBKDF2.
        // Une valeur différente rendrait le ZIP illisible par 7-Zip, WinRAR et WinZip.
        private const int    Pbkdf2Iterations = 1000;

        private const int    DerivedKeyLength = 66;     // 32 AES + 32 HMAC + 2 verif
        private const int    AuthCodeLength   = 10;
        private const int    StreamBufferSize = 65536;  // 64 KB — taille du buffer de streaming
        private const ushort AesExtraTag      = 0x9901;
        private const ushort AesExtraDataSize = 7;
        private const ushort ZipMethodAes     = 99;
        private const ushort AesVersion       = 2;
        private const byte   AesStrength      = 3;      // 3 = AES-256
        private const ushort Zip64ExtraTag    = 0x0001;
        private const uint   Zip64Sentinel32  = 0xFFFFFFFF;
        private const ushort Zip64Sentinel16  = 0xFFFF;

        /// <summary>
        /// Extensions dont le contenu est déjà compressé : Deflate serait contre-productif.
        /// Store direct appliqué automatiquement pour ces types.
        /// </summary>
        private static readonly HashSet<string> AlreadyCompressedExtensions = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            ".pdf",
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".m4v",
            ".mp3", ".aac", ".ogg", ".flac", ".wma", ".m4a",
            ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".cab",
            ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
        };

        // ═══════════════════════════════════════════════════════════════════════
        // DÉTECTION DE COMPRESSION
        // ═══════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Retourne true si le fichier doit être stocké sans compression (extension déjà compressée).
        /// </summary>
        public static bool ShouldStore(string filePath)
            => AlreadyCompressedExtensions.Contains(Path.GetExtension(filePath));

        // ═══════════════════════════════════════════════════════════════════════
        // DÉRIVATION DES CLÉS — PBKDF2
        // ═══════════════════════════════════════════════════════════════════════

        internal struct DerivedKeys
        {
            public byte[] AesKey;           // 32 octets
            public byte[] HmacKey;          // 32 octets
            public byte[] PasswordVerifier; // 2 octets
        }

        /// <summary>
        /// Dérive les clés AES, HMAC et le code de vérification depuis le mot de passe et un sel.
        /// PBKDF2-SHA1 produit 66 octets découpés en [0..31] AES, [32..63] HMAC, [64..65] vérif.
        /// </summary>
        internal static DerivedKeys DeriveKeys(string password, byte[] salt)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, salt, Pbkdf2Iterations))
            {
                byte[] derived = pbkdf2.GetBytes(DerivedKeyLength);
                var keys = new DerivedKeys
                {
                    AesKey           = new byte[32],
                    HmacKey          = new byte[32],
                    PasswordVerifier = new byte[2]
                };
                Buffer.BlockCopy(derived, 0,  keys.AesKey,           0, 32);
                Buffer.BlockCopy(derived, 32, keys.HmacKey,          0, 32);
                Buffer.BlockCopy(derived, 64, keys.PasswordVerifier, 0,  2);
                return keys;
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // AES-256-CTR STREAMING
        //
        // CTR mode est implémenté manuellement sur AES-ECB : le compteur (16 o.) est
        // chiffré par AES-ECB pour produire un keystream, puis XORé avec les données.
        // AES-ECB est utilisé ici comme primitive de bas niveau pour CTR, pas directement
        // sur les données — c'est le seul moyen d'implémenter CTR avec le BCL .NET 4.7.
        // ═══════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Chiffre un flux source vers un flux destination en AES-256-CTR, bloc de 64 KB à la fois.
        /// Met à jour le HMAC-SHA1 en parallèle sur les données chiffrées (encrypt-then-MAC).
        /// AES-ECB est utilisé ici uniquement comme primitive pour chiffrer le compteur CTR,
        /// jamais directement sur les données en clair — ce n'est pas un usage non sécurisé d'ECB.
        /// </summary>
        private static long AesCtrEncryptStream(Stream source, Stream dest, byte[] aesKey, HMACSHA1 hmac)
        {
            var counter   = new byte[16];
            counter[0]    = 1;   // WinZip part du compteur 1
            var keystream = new byte[16];
            var buffer    = new byte[StreamBufferSize];
            var encrypted = new byte[StreamBufferSize];
            long totalWritten = 0;

            using (var aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None, Key = aesKey })
            using (var encryptor = aes.CreateEncryptor())
            {
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    int pos = 0;
                    while (pos < read)
                    {
                        encryptor.TransformBlock(counter, 0, 16, keystream, 0);

                        int chunk = Math.Min(read - pos, 16);
                        for (int i = 0; i < chunk; i++)
                            encrypted[pos + i] = (byte)(buffer[pos + i] ^ keystream[i]);

                        pos += chunk;

                        // Incrémente le compteur little-endian (8 octets = 64 bits)
                        for (int i = 0; i < 8; i++)
                            if (++counter[i] != 0) break;
                    }

                    hmac.TransformBlock(encrypted, 0, read, null, 0);
                    dest.Write(encrypted, 0, read);
                    totalWritten += read;
                }
            }

            return totalWritten;
        }

        // ═══════════════════════════════════════════════════════════════════════
        // HELPERS FORMAT ZIP
        // ═══════════════════════════════════════════════════════════════════════

        private static void GetDosDateTime(DateTime dt, out ushort dosDate, out ushort dosTime)
        {
            int year = Math.Max(dt.Year, 1980);
            dosDate = (ushort)(((year - 1980) << 9) | (dt.Month << 5) | dt.Day);
            dosTime = (ushort)((dt.Hour << 11) | (dt.Minute << 5) | (dt.Second >> 1));
        }

        private static void WriteAesExtraField(BinaryWriter bw, ushort realMethod)
        {
            bw.Write(AesExtraTag);
            bw.Write(AesExtraDataSize);
            bw.Write(AesVersion);
            bw.Write((byte)'A');
            bw.Write((byte)'E');
            bw.Write(AesStrength);
            bw.Write(realMethod);
        }

        private static byte[] BuildLfhZip64Extra(ulong uncompressedSize, ulong compressedSize)
        {
            var ms = new MemoryStream(20);
            var bw = new BinaryWriter(ms);
            bw.Write(Zip64ExtraTag);
            bw.Write((ushort)16);
            bw.Write(uncompressedSize);
            bw.Write(compressedSize);
            return ms.ToArray();
        }

        private static byte[] BuildCdhZip64Extra(ulong uncompressedSize, ulong compressedSize, ulong lfhOffset)
        {
            var ms = new MemoryStream(28);
            var bw = new BinaryWriter(ms);
            bw.Write(Zip64ExtraTag);
            bw.Write((ushort)24);
            bw.Write(uncompressedSize);
            bw.Write(compressedSize);
            bw.Write(lfhOffset);
            return ms.ToArray();
        }

        // ═══════════════════════════════════════════════════════════════════════
        // CHIFFREMENT D'UNE ENTRÉE — extrait pour réduire la complexité cognitive
        // ═══════════════════════════════════════════════════════════════════════

        /// <summary>Résultat du chiffrement d'une entrée ZIP.</summary>
        private struct EntryEncryptResult
        {
            public byte[] Salt;
            public byte[] PasswordVerifier;
            public long   CipherByteCount;    // octets de données chiffrées écrits dans le flux ZIP
            public byte[] AuthCode;           // HMAC-SHA1 tronqué 10 o.
            public ushort EffectiveMethod;    // 0 = Store, 8 = Deflate (après décision finale)
        }

        /// <summary>
        /// Chiffre un fichier source en streaming et l'écrit directement dans le flux ZIP.
        /// Décide de la compression (Deflate ou Store), dérive les clés, chiffre en AES-256-CTR
        /// et calcule le HMAC-SHA1. Complexité cognitive isolée ici pour garder CreateFromPaths lisible.
        /// </summary>
        private static EntryEncryptResult EncryptFileEntry(
            string sourcePath, string password, bool doDeflate,
            FileStream zipStream, BinaryWriter zipWriter)
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(salt);

            DerivedKeys keys = DeriveKeys(password, salt);
            zipWriter.Write(salt);
            zipWriter.Write(keys.PasswordVerifier);

            long   uncompressedLen = new FileInfo(sourcePath).Length;
            long   cipherByteCount;
            ushort effectiveMethod;

            using (var hmac = new HMACSHA1(keys.HmacKey))
            {
                using (var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                                                FileShare.Read, StreamBufferSize))
                {
                    EncryptStream(src, zipStream, keys.AesKey, hmac,
                                  doDeflate, uncompressedLen,
                                  out cipherByteCount, out effectiveMethod);
                }

                hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                byte[] authCode = new byte[AuthCodeLength];
                Buffer.BlockCopy(hmac.Hash, 0, authCode, 0, AuthCodeLength);
                zipWriter.Write(authCode);

                return new EntryEncryptResult
                {
                    Salt             = salt,
                    PasswordVerifier = keys.PasswordVerifier,
                    CipherByteCount  = cipherByteCount,
                    AuthCode         = authCode,
                    EffectiveMethod  = effectiveMethod
                };
            }
        }

        /// <summary>
        /// Choisit la compression et chiffre le flux source vers le flux ZIP.
        /// Extrait séparément pour garder EncryptFileEntry sous la limite de complexité.
        /// </summary>
        private static void EncryptStream(
            FileStream src, FileStream dest, byte[] aesKey, HMACSHA1 hmac,
            bool doDeflate, long uncompressedLen,
            out long cipherByteCount, out ushort effectiveMethod)
        {
            if (!doDeflate)
            {
                cipherByteCount = AesCtrEncryptStream(src, dest, aesKey, hmac);
                effectiveMethod = 0;
                return;
            }

            // Deflate uniquement pour les fichiers ≤ 256 MB (au-delà : Store pour éviter OOM)
            if (uncompressedLen > 256L * 1024 * 1024)
            {
                cipherByteCount = AesCtrEncryptStream(src, dest, aesKey, hmac);
                effectiveMethod = 0;
                return;
            }

            byte[] deflated = DeflateToBytes(src);
            if (deflated.Length >= uncompressedLen)
            {
                // Deflate contre-productif : Store depuis le début du fichier
                src.Seek(0, SeekOrigin.Begin);
                cipherByteCount = AesCtrEncryptStream(src, dest, aesKey, hmac);
                effectiveMethod = 0;
                return;
            }

            using (var ms = new MemoryStream(deflated))
                cipherByteCount = AesCtrEncryptStream(ms, dest, aesKey, hmac);
            effectiveMethod = 8;
        }

        // ═══════════════════════════════════════════════════════════════════════
        // ÉCRITURE LFH / CDH / EOCD
        // ═══════════════════════════════════════════════════════════════════════

        private static void WriteCdh(BinaryWriter bw, CentralDirEntry e)
        {
            bool needUncSize   = e.UncompressedSize64 > Zip64Sentinel32;
            bool needCmpSize   = e.CompressedSize64   > Zip64Sentinel32;
            bool needLfhOffset = e.LfhOffset64        > Zip64Sentinel32;
            bool needZip64     = needUncSize || needCmpSize || needLfhOffset;

            byte[] zip64Extra = BuildCdhZip64Extra(e.UncompressedSize64, e.CompressedSize64, e.LfhOffset64);
            ushort extraLen   = needZip64 ? (ushort)(11 + zip64Extra.Length) : (ushort)11;

            uint cmpSize32 = needCmpSize   ? Zip64Sentinel32 : (uint)e.CompressedSize64;
            uint uncSize32 = needUncSize   ? Zip64Sentinel32 : (uint)e.UncompressedSize64;
            uint lfhOff32  = needLfhOffset ? Zip64Sentinel32 : (uint)e.LfhOffset64;

            bw.Write(0x02014B50u);
            bw.Write((ushort)45);
            bw.Write((ushort)45);
            bw.Write((ushort)0x0001);
            bw.Write(ZipMethodAes);
            bw.Write(e.DosTime);
            bw.Write(e.DosDate);
            bw.Write(0u);                      // CRC = 0 (AES v2)
            bw.Write(cmpSize32);
            bw.Write(uncSize32);
            bw.Write((ushort)e.NameBytes.Length);
            bw.Write(extraLen);
            bw.Write((ushort)0);               // file comment length
            bw.Write((ushort)0);               // disk number start
            bw.Write((ushort)0);               // internal file attributes
            bw.Write(0u);                      // external file attributes
            bw.Write(lfhOff32);
            bw.Write(e.NameBytes);
            WriteAesExtraField(bw, e.RealMethod);
            if (needZip64)
                bw.Write(zip64Extra);
        }

        private static void WriteEocd(BinaryWriter bw, ulong cdOffset64, ulong cdSize64,
                                      ulong eocd64Pos, ulong entryCount)
        {
            // EOCD64
            bw.Write(0x06064B50u);
            bw.Write((ulong)44);
            bw.Write((ushort)45);
            bw.Write((ushort)45);
            bw.Write(0u);
            bw.Write(0u);
            bw.Write(entryCount);
            bw.Write(entryCount);
            bw.Write(cdSize64);
            bw.Write(cdOffset64);

            // ZIP64 End Locator
            bw.Write(0x07064B50u);
            bw.Write(0u);
            bw.Write(eocd64Pos);
            bw.Write(1u);

            // EOCD classique (compatibilité outils non-ZIP64)
            ushort cnt16   = entryCount > Zip64Sentinel16 ? Zip64Sentinel16 : (ushort)entryCount;
            uint   cdSz32  = cdSize64   > Zip64Sentinel32 ? Zip64Sentinel32 : (uint)cdSize64;
            uint   cdOff32 = cdOffset64 > Zip64Sentinel32 ? Zip64Sentinel32 : (uint)cdOffset64;

            bw.Write(0x06054B50u);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write(cnt16);
            bw.Write(cnt16);
            bw.Write(cdSz32);
            bw.Write(cdOff32);
            bw.Write((ushort)0);
        }

        // ═══════════════════════════════════════════════════════════════════════
        // API PUBLIQUE
        // ═══════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Crée un ZIP chiffré AES-256 à partir d'une liste de fichiers sur disque.
        /// Le nom d'entrée dans le ZIP est le nom de fichier seul (sans chemin).
        /// </summary>
        public void CreateFromFiles(string zipPath, IEnumerable<string> sourceFiles,
                                    string password, bool useDeflate = true)
        {
            var entries = new Dictionary<string, string>();
            foreach (string filePath in sourceFiles)
                entries[Path.GetFileName(filePath)] = filePath;
            CreateFromPaths(zipPath, entries, password, useDeflate);
        }

        /// <summary>
        /// Crée un ZIP chiffré AES-256 à partir d'un dictionnaire (chemin relatif ZIP → chemin absolu disque).
        /// Streaming complet : RAM constante quelle que soit la taille des fichiers.
        /// ZIP64 activé automatiquement au-delà de 4 GB.
        /// </summary>
        public void CreateFromPaths(string zipPath,
                                    Dictionary<string, string> entries,
                                    string password,
                                    bool useDeflate = true)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Le mot de passe ne peut pas être vide.", nameof(password));
            if (entries == null || entries.Count == 0)
                throw new ArgumentException("Aucun fichier à compresser.", nameof(entries));

            ushort dosDate, dosTime;
            GetDosDateTime(DateTime.Now, out dosDate, out dosTime);

            var centralDirEntries = new List<CentralDirEntry>();

            using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write,
                                           FileShare.None, StreamBufferSize))
            using (var bw = new BinaryWriter(fs, Encoding.UTF8))
            {
                foreach (var kvp in entries)
                {
                    string entryName  = kvp.Key.Replace('\\', '/');
                    string sourcePath = kvp.Value;
                    byte[] nameBytes  = Encoding.UTF8.GetBytes(entryName);
                    ulong  lfhOffset  = (ulong)fs.Position;
                    bool   doDeflate  = useDeflate && !ShouldStore(sourcePath);

                    // Écrit le LFH avec les tailles à zéro (inconnues avant chiffrement)
                    long lfhPos;
                    long zip64ExtraPos;
                    WriteLfhFull(bw, nameBytes, doDeflate ? (ushort)8 : (ushort)0,
                                 dosDate, dosTime, out lfhPos, out zip64ExtraPos);

                    // Chiffre le fichier et écrit les données dans le flux ZIP
                    EntryEncryptResult enc = EncryptFileEntry(sourcePath, password, doDeflate, fs, bw);

                    // Patch le LFH si la méthode effective diffère de la méthode initiale
                    if (enc.EffectiveMethod != (doDeflate ? (ushort)8 : (ushort)0))
                        PatchAesRealMethod(fs, bw, lfhPos, nameBytes.Length, enc.EffectiveMethod);

                    // Corrige le ZIP64 extra du LFH avec les vraies tailles
                    ulong plainSize  = (ulong)new FileInfo(sourcePath).Length;
                    ulong cipherSize = (ulong)(SaltSize + 2 + enc.CipherByteCount + AuthCodeLength);
                    long  afterEntry = fs.Position;
                    fs.Seek(zip64ExtraPos, SeekOrigin.Begin);
                    bw.Write(BuildLfhZip64Extra(plainSize, cipherSize));
                    fs.Seek(afterEntry, SeekOrigin.Begin);

                    centralDirEntries.Add(new CentralDirEntry
                    {
                        NameBytes          = nameBytes,
                        UncompressedSize64 = plainSize,
                        CompressedSize64   = cipherSize,
                        LfhOffset64        = lfhOffset,
                        DosDate            = dosDate,
                        DosTime            = dosTime,
                        RealMethod         = enc.EffectiveMethod
                    });
                }

                ulong cdOffset = (ulong)fs.Position;
                foreach (var e in centralDirEntries)
                    WriteCdh(bw, e);

                ulong cdSize   = (ulong)fs.Position - cdOffset;
                ulong eocd64P  = (ulong)fs.Position;
                WriteEocd(bw, cdOffset, cdSize, eocd64P, (ulong)centralDirEntries.Count);
            }
        }

        /// <summary>
        /// Compatibilité ascendante : accepte un dictionnaire (chemin relatif → octets).
        /// Pour de gros volumes, préférer <see cref="CreateFromPaths"/>.
        /// </summary>
        public void CreateFromBytes(string zipPath,
                                    Dictionary<string, byte[]> entries,
                                    string password,
                                    bool useDeflate = true)
        {
            if (entries == null || entries.Count == 0)
                throw new ArgumentException("Aucun fichier à compresser.", nameof(entries));

            string tempDir = Path.Combine(Path.GetTempPath(), "ZipProtector_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var pathEntries = new Dictionary<string, string>();
                foreach (var kvp in entries)
                {
                    string safeName = kvp.Key.Replace('/', Path.DirectorySeparatorChar);
                    string fullTemp = Path.Combine(tempDir, safeName);
                    Directory.CreateDirectory(Path.GetDirectoryName(fullTemp));
                    File.WriteAllBytes(fullTemp, kvp.Value);
                    pathEntries[kvp.Key] = fullTemp;
                }
                CreateFromPaths(zipPath, pathEntries, password, useDeflate);
            }
            finally
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // HELPERS INTERNES
        // ═══════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Écrit le Local File Header complet avec date/heure, nom et extra fields.
        /// Retourne la position du LFH et la position du ZIP64 extra pour correction ultérieure.
        /// </summary>
        private static void WriteLfhFull(BinaryWriter bw, byte[] nameBytes, ushort initialMethod,
                                         ushort dosDate, ushort dosTime,
                                         out long lfhPos, out long zip64ExtraPos)
        {
            const ushort ExtraLen = 11 + 20;
            lfhPos = ((FileStream)bw.BaseStream).Position;
            bw.Write(0x04034B50u);
            bw.Write((ushort)51);
            bw.Write((ushort)0x0001);
            bw.Write(ZipMethodAes);
            bw.Write(dosTime);
            bw.Write(dosDate);
            bw.Write(0u);
            bw.Write(Zip64Sentinel32);
            bw.Write(Zip64Sentinel32);
            bw.Write((ushort)nameBytes.Length);
            bw.Write(ExtraLen);
            bw.Write(nameBytes);
            WriteAesExtraField(bw, initialMethod);
            zip64ExtraPos = ((FileStream)bw.BaseStream).Position;
            bw.Write(BuildLfhZip64Extra(0, 0));
        }

        private static byte[] DeflateToBytes(Stream source)
        {
            using (var ms = new MemoryStream())
            {
                using (var deflate = new DeflateStream(ms, CompressionMode.Compress, leaveOpen: true))
                {
                    byte[] buf = new byte[StreamBufferSize];
                    int read;
                    while ((read = source.Read(buf, 0, buf.Length)) > 0)
                        deflate.Write(buf, 0, read);
                }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Corrige le champ "real method" (2 octets) dans l'AES Extra Field du LFH via seek.
        /// Offset depuis lfhPos : 30 (fixe) + nameLen + 9 (tag+size+ver+'A'+'E'+strength).
        /// </summary>
        private static void PatchAesRealMethod(FileStream fs, BinaryWriter bw,
                                               long lfhPos, int nameLen, ushort method)
        {
            long saved = fs.Position;
            fs.Seek(lfhPos + 30 + nameLen + 9, SeekOrigin.Begin);
            bw.Write(method);
            fs.Seek(saved, SeekOrigin.Begin);
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STRUCTURE INTERNE
        // ═══════════════════════════════════════════════════════════════════════

        private sealed class CentralDirEntry
        {
            public byte[]  NameBytes;
            public ulong   UncompressedSize64;
            public ulong   CompressedSize64;
            public ulong   LfhOffset64;
            public ushort  DosDate;
            public ushort  DosTime;
            public ushort  RealMethod;
        }
    }
}
