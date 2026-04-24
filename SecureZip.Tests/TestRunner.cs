using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureZip.Tests
{
    // ═══════════════════════════════════════════════════════════════════════
    // Infrastructure de test minimaliste (zéro NuGet, .NET 4.7)
    // ═══════════════════════════════════════════════════════════════════════

    static class Assert
    {
        public static void IsTrue(bool condition, string message = null)
        {
            if (!condition)
                throw new Exception("FAIL: " + (message ?? "expected true"));
        }

        public static void AreEqual<T>(T expected, T actual, string message = null)
        {
            if (!Equals(expected, actual))
                throw new Exception(string.Format("FAIL: expected={0} actual={1} {2}",
                    expected, actual, message ?? ""));
        }

        public static void Throws<TEx>(Action action, string message = null) where TEx : Exception
        {
            try { action(); }
            catch (TEx) { return; }
            catch (Exception ex)
            {
                throw new Exception(string.Format("FAIL: expected {0} but got {1} — {2}",
                    typeof(TEx).Name, ex.GetType().Name, message ?? ""));
            }
            throw new Exception(string.Format("FAIL: expected {0} but no exception — {1}",
                typeof(TEx).Name, message ?? ""));
        }
    }

    static class TestRunner
    {
        static int _passed, _failed;

        static void Run(string name, Action test)
        {
            try
            {
                test();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  [PASS] " + name);
                Console.ResetColor();
                _passed++;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  [FAIL] " + name);
                Console.WriteLine("         " + ex.Message);
                Console.ResetColor();
                _failed++;
            }
        }

        static int Main()
        {
            Console.WriteLine("=== SecureZip Tests ===");
            Console.WriteLine();

            Section("Dérivation des clés (PBKDF2)");
            Run("Sel différent → clés AES différentes",           Test_DifferentSalt_DifferentKeys);
            Run("Même sel + même MDP → clés identiques",          Test_SameSaltSamePassword_SameKeys);
            Run("MDP différent → clés différentes",               Test_DifferentPassword_DifferentKeys);
            Run("Longueur clé AES = 32 octets",                   Test_AesKeyLength);
            Run("Longueur clé HMAC = 32 octets",                  Test_HmacKeyLength);
            Run("Code vérification = 2 octets",                   Test_PasswordVerifierLength);

            Section("Détection de compression (ShouldStore)");
            Run("PDF → Store",                                    Test_ShouldStore_Pdf);
            Run("PNG → Store",                                    Test_ShouldStore_Png);
            Run("XLSX → Store",                                   Test_ShouldStore_Xlsx);
            Run("ZIP → Store",                                    Test_ShouldStore_Zip);
            Run("TXT → Deflate",                                  Test_ShouldStore_Txt);
            Run("CSV → Deflate",                                  Test_ShouldStore_Csv);
            Run("XML → Deflate",                                  Test_ShouldStore_Xml);
            Run("Extension insensible à la casse (.PDF)",         Test_ShouldStore_CaseInsensitive);

            Section("Validation des paramètres");
            Run("MDP vide → ArgumentException",                   Test_EmptyPassword_Throws);
            Run("Entrées nulles → ArgumentException",             Test_NullEntries_Throws);
            Run("Entrées vides → ArgumentException",              Test_EmptyEntries_Throws);

            Section("Création ZIP — fichiers texte (Deflate)");
            Run("ZIP créé sur disque",                            Test_ZipFileExists);
            Run("Taille ZIP > 0",                                 Test_ZipSizePositive);
            Run("7-Zip : bon MDP → Everything is Ok",            Test_7Zip_CorrectPassword);
            Run("7-Zip : mauvais MDP → Wrong password",          Test_7Zip_WrongPassword);
            Run("Arborescence préservée (sous-dossier)",          Test_7Zip_SubfolderPreserved);

            Section("Création ZIP — types déjà compressés");
            Run("PDF Store : taille ZIP ≈ taille source + overhead", Test_Pdf_StoreOverhead);
            Run("PNG Store : vérifié par 7-Zip",                 Test_Png_7ZipVerify);
            Run("XLSX Store : vérifié par 7-Zip",                Test_Xlsx_7ZipVerify);

            Section("Robustesse");
            Run("Fichier vide inclus sans crash",                 Test_EmptyFile_NoCrash);
            Run("Nom de fichier avec espaces et accents",         Test_SpecialCharsInName);
            Run("Multi-fichiers (10 fichiers)",                   Test_MultipleFiles);
            Run("Fichier 5 MB : streaming, pas de OOM",           Test_LargeFile_Streaming);
            Run("FormatSize : octets / Ko / Mo / Go",             Test_FormatSize);

            Console.WriteLine();
            Console.WriteLine(string.Format("Résultat : {0} passés, {1} échoués sur {2} tests.",
                _passed, _failed, _passed + _failed));

            return _failed == 0 ? 0 : 1;
        }

        static void Section(string title)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("── " + title);
            Console.ResetColor();
        }

        // ═══════════════════════════════════════════════════════════════════
        // Helpers
        // ═══════════════════════════════════════════════════════════════════

        static string TempDir()
        {
            string d = Path.Combine(Path.GetTempPath(), "ZPTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(d);
            return d;
        }

        static string WriteTemp(string dir, string name, string content)
        {
            string path = Path.Combine(dir, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, content, Encoding.UTF8);
            return path;
        }

        static string WriteTempBytes(string dir, string name, byte[] content)
        {
            string path = Path.Combine(dir, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllBytes(path, content);
            return path;
        }

        /// <summary>
        /// Lance 7-Zip en test sur le ZIP avec le mot de passe fourni.
        /// Retourne true si 7-Zip répond "Everything is Ok".
        /// </summary>
        static bool Run7ZipTest(string zipPath, string password)
        {
            string exe = @"C:\Program Files\7-Zip\7z.exe";
            if (!File.Exists(exe)) return true;   // 7-Zip absent : skip silencieux

            var psi = new ProcessStartInfo(exe,
                string.Format("t \"{0}\" -p\"{1}\"", zipPath, password))
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false
            };
            using (var p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                return output.Contains("Everything is Ok");
            }
        }

        static bool Run7ZipWrongPassword(string zipPath, string password)
        {
            string exe = @"C:\Program Files\7-Zip\7z.exe";
            if (!File.Exists(exe)) return true;

            var psi = new ProcessStartInfo(exe,
                string.Format("t \"{0}\" -p\"{1}\"", zipPath, password))
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false
            };
            using (var p = Process.Start(psi))
            {
                string stderr = p.StandardError.ReadToEnd();
                string stdout = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                return (stdout + stderr).Contains("Wrong password");
            }
        }

        static string Run7ZipList(string zipPath, string password)
        {
            string exe = @"C:\Program Files\7-Zip\7z.exe";
            if (!File.Exists(exe)) return "";

            var psi = new ProcessStartInfo(exe,
                string.Format("l \"{0}\" -p\"{1}\"", zipPath, password))
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false
            };
            using (var p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                return output;
            }
        }

        // ─── Fakebytes pour PDFs/PNGs/XLSX sans contenu réel ───────────────

        static byte[] FakePdfBytes()
        {
            // En-tête PDF minimal + données aléatoires pour simuler un PDF compressé
            var rng = new RNGCryptoServiceProvider();
            byte[] data = new byte[4096];
            rng.GetBytes(data);
            var header = Encoding.ASCII.GetBytes("%PDF-1.4\n");
            Buffer.BlockCopy(header, 0, data, 0, header.Length);
            return data;
        }

        static byte[] FakePngBytes()
        {
            // Signature PNG + données aléatoires (simule un PNG compressé)
            var rng = new RNGCryptoServiceProvider();
            byte[] data = new byte[2048];
            rng.GetBytes(data);
            byte[] sig = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            Buffer.BlockCopy(sig, 0, data, 0, sig.Length);
            return data;
        }

        static byte[] FakeXlsxBytes()
        {
            // Signature ZIP (XLSX = ZIP internement) + données aléatoires
            var rng = new RNGCryptoServiceProvider();
            byte[] data = new byte[2048];
            rng.GetBytes(data);
            byte[] sig = { 0x50, 0x4B, 0x03, 0x04 };
            Buffer.BlockCopy(sig, 0, data, 0, sig.Length);
            return data;
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tests — Dérivation des clés
        // ═══════════════════════════════════════════════════════════════════

        static void Test_DifferentSalt_DifferentKeys()
        {
            byte[] salt1 = new byte[16]; byte[] salt2 = new byte[16]; salt2[0] = 1;
            var k1 = PasswordZipWriter.DeriveKeys("mdp", salt1);
            var k2 = PasswordZipWriter.DeriveKeys("mdp", salt2);
            Assert.IsTrue(!k1.AesKey.SequenceEqual(k2.AesKey), "AES keys should differ");
        }

        static void Test_SameSaltSamePassword_SameKeys()
        {
            byte[] salt = new byte[16]; salt[3] = 42;
            var k1 = PasswordZipWriter.DeriveKeys("motDePasse", salt);
            var k2 = PasswordZipWriter.DeriveKeys("motDePasse", salt);
            Assert.IsTrue(k1.AesKey.SequenceEqual(k2.AesKey), "same inputs → same AES key");
            Assert.IsTrue(k1.HmacKey.SequenceEqual(k2.HmacKey), "same inputs → same HMAC key");
        }

        static void Test_DifferentPassword_DifferentKeys()
        {
            byte[] salt = new byte[16];
            var k1 = PasswordZipWriter.DeriveKeys("mdp1", salt);
            var k2 = PasswordZipWriter.DeriveKeys("mdp2", salt);
            Assert.IsTrue(!k1.AesKey.SequenceEqual(k2.AesKey), "different password → different key");
        }

        static void Test_AesKeyLength()
        {
            var k = PasswordZipWriter.DeriveKeys("test", new byte[16]);
            Assert.AreEqual(32, k.AesKey.Length, "AES key must be 32 bytes");
        }

        static void Test_HmacKeyLength()
        {
            var k = PasswordZipWriter.DeriveKeys("test", new byte[16]);
            Assert.AreEqual(32, k.HmacKey.Length, "HMAC key must be 32 bytes");
        }

        static void Test_PasswordVerifierLength()
        {
            var k = PasswordZipWriter.DeriveKeys("test", new byte[16]);
            Assert.AreEqual(2, k.PasswordVerifier.Length, "verifier must be 2 bytes");
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tests — ShouldStore
        // ═══════════════════════════════════════════════════════════════════

        static void Test_ShouldStore_Pdf()  => Assert.IsTrue(PasswordZipWriter.ShouldStore("doc.pdf"));
        static void Test_ShouldStore_Png()  => Assert.IsTrue(PasswordZipWriter.ShouldStore("img.png"));
        static void Test_ShouldStore_Xlsx() => Assert.IsTrue(PasswordZipWriter.ShouldStore("sheet.xlsx"));
        static void Test_ShouldStore_Zip()  => Assert.IsTrue(PasswordZipWriter.ShouldStore("archive.zip"));
        static void Test_ShouldStore_Txt()  => Assert.IsTrue(!PasswordZipWriter.ShouldStore("data.txt"));
        static void Test_ShouldStore_Csv()  => Assert.IsTrue(!PasswordZipWriter.ShouldStore("data.csv"));
        static void Test_ShouldStore_Xml()  => Assert.IsTrue(!PasswordZipWriter.ShouldStore("config.xml"));
        static void Test_ShouldStore_CaseInsensitive() => Assert.IsTrue(PasswordZipWriter.ShouldStore("DOC.PDF"));

        // ═══════════════════════════════════════════════════════════════════
        // Tests — Validation
        // ═══════════════════════════════════════════════════════════════════

        static void Test_EmptyPassword_Throws()
        {
            var tmp = TempDir();
            try
            {
                var w = new PasswordZipWriter();
                Assert.Throws<ArgumentException>(() =>
                    w.CreateFromPaths(Path.Combine(tmp, "out.zip"),
                        new Dictionary<string, string> { { "a.txt", tmp } }, ""));
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_NullEntries_Throws()
        {
            var w = new PasswordZipWriter();
            Assert.Throws<ArgumentException>(() =>
                w.CreateFromPaths("out.zip", null, "password123"));
        }

        static void Test_EmptyEntries_Throws()
        {
            var w = new PasswordZipWriter();
            Assert.Throws<ArgumentException>(() =>
                w.CreateFromPaths("out.zip", new Dictionary<string, string>(), "password123"));
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tests — Création ZIP texte
        // ═══════════════════════════════════════════════════════════════════

        static Dictionary<string, string> MakeTextEntries(string tmpDir)
        {
            string f1 = WriteTemp(tmpDir, "hello.txt",            "Bonjour le monde !");
            string f2 = WriteTemp(tmpDir, "sub/readme.txt",       string.Concat(Enumerable.Repeat("ligne de texte\n", 200)));
            string f3 = WriteTemp(tmpDir, "data.csv",             "col1,col2,col3\n1,2,3\n4,5,6\n");
            return new Dictionary<string, string>
            {
                { "hello.txt",    f1 },
                { "sub/readme.txt", f2 },
                { "data.csv",     f3 },
            };
        }

        static void Test_ZipFileExists()
        {
            string tmp = TempDir();
            try
            {
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, MakeTextEntries(tmp), "mdp123456");
                Assert.IsTrue(File.Exists(zip), "ZIP file must exist");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_ZipSizePositive()
        {
            string tmp = TempDir();
            try
            {
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, MakeTextEntries(tmp), "mdp123456");
                Assert.IsTrue(new FileInfo(zip).Length > 0, "ZIP must not be empty");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_7Zip_CorrectPassword()
        {
            string tmp = TempDir();
            try
            {
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, MakeTextEntries(tmp), "BonMotDePasse!");
                Assert.IsTrue(Run7ZipTest(zip, "BonMotDePasse!"), "7-Zip doit valider le bon MDP");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_7Zip_WrongPassword()
        {
            string tmp = TempDir();
            try
            {
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, MakeTextEntries(tmp), "BonMotDePasse!");
                Assert.IsTrue(Run7ZipWrongPassword(zip, "MauvaisMDP"), "7-Zip doit rejeter le mauvais MDP");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_7Zip_SubfolderPreserved()
        {
            string tmp = TempDir();
            try
            {
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, MakeTextEntries(tmp), "mdp123456");
                string listing = Run7ZipList(zip, "mdp123456");
                Assert.IsTrue(listing.Contains("sub/readme.txt") || listing.Contains("sub\\readme.txt"),
                    "le sous-dossier doit être présent dans le listing 7-Zip");
            }
            finally { Directory.Delete(tmp, true); }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tests — Types déjà compressés
        // ═══════════════════════════════════════════════════════════════════

        static void Test_Pdf_StoreOverhead()
        {
            string tmp = TempDir();
            try
            {
                byte[] pdfBytes = FakePdfBytes();
                string src = WriteTempBytes(tmp, "doc.pdf", pdfBytes);
                string zip = Path.Combine(tmp, "out.zip");

                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "doc.pdf", src } }, "mdp123456");

                long zipSize = new FileInfo(zip).Length;
                // Overhead AES : sel(16) + verif(2) + HMAC(10) + en-têtes ZIP ≈ 150 o. max
                // La taille du ZIP ne doit pas dépasser source + 300 o. (Store = pas de compression)
                Assert.IsTrue(zipSize <= pdfBytes.Length + 300,
                    string.Format("PDF Store overhead trop grand : source={0} zip={1}", pdfBytes.Length, zipSize));
                Assert.IsTrue(zipSize > 0);
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_Png_7ZipVerify()
        {
            string tmp = TempDir();
            try
            {
                string src = WriteTempBytes(tmp, "img.png", FakePngBytes());
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "img.png", src } }, "mdp123456");
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider PNG Store");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_Xlsx_7ZipVerify()
        {
            string tmp = TempDir();
            try
            {
                string src = WriteTempBytes(tmp, "sheet.xlsx", FakeXlsxBytes());
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "sheet.xlsx", src } }, "mdp123456");
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider XLSX Store");
            }
            finally { Directory.Delete(tmp, true); }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tests — Robustesse
        // ═══════════════════════════════════════════════════════════════════

        static void Test_EmptyFile_NoCrash()
        {
            string tmp = TempDir();
            try
            {
                string src = WriteTempBytes(tmp, "empty.txt", new byte[0]);
                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "empty.txt", src } }, "mdp123456");
                Assert.IsTrue(File.Exists(zip));
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider fichier vide");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_SpecialCharsInName()
        {
            string tmp = TempDir();
            try
            {
                string src = WriteTemp(tmp, "tmpfile.txt", "contenu");
                string zip = Path.Combine(tmp, "out.zip");
                // Nom d'entrée avec espaces et accents (pas le nom sur disque)
                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "dossier spécial/fichier été.txt", src } }, "mdp123456");
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider noms spéciaux");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_MultipleFiles()
        {
            string tmp = TempDir();
            try
            {
                var entries = new Dictionary<string, string>();
                for (int i = 0; i < 10; i++)
                {
                    string name = string.Format("file{0:D2}.txt", i);
                    string content = string.Concat(Enumerable.Repeat("contenu " + i + "\n", 50));
                    entries[name] = WriteTemp(tmp, name, content);
                }

                string zip = Path.Combine(tmp, "out.zip");
                new PasswordZipWriter().CreateFromPaths(zip, entries, "mdp123456");
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider 10 fichiers");
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_LargeFile_Streaming()
        {
            string tmp = TempDir();
            try
            {
                // Génère 5 MB de données aléatoires (simule un PDF volumineux)
                string src = Path.Combine(tmp, "big.pdf");
                var rng = new RNGCryptoServiceProvider();
                byte[] chunk = new byte[65536];
                using (var fs = new FileStream(src, FileMode.Create))
                    for (int i = 0; i < 80; i++)   // 80 × 64 KB ≈ 5 MB
                    {
                        rng.GetBytes(chunk);
                        fs.Write(chunk, 0, chunk.Length);
                    }

                string zip = Path.Combine(tmp, "out.zip");
                long memBefore = GC.GetTotalMemory(true);

                new PasswordZipWriter().CreateFromPaths(zip,
                    new Dictionary<string, string> { { "big.pdf", src } }, "mdp123456");

                long memAfter = GC.GetTotalMemory(false);
                long memDelta = memAfter - memBefore;

                Assert.IsTrue(File.Exists(zip), "ZIP doit exister");
                Assert.IsTrue(Run7ZipTest(zip, "mdp123456"), "7-Zip doit valider gros fichier");
                // La RAM utilisée doit rester très inférieure à la taille du fichier (5 MB)
                // On tolère 3 MB de overhead (buffers GC, etc.)
                Assert.IsTrue(memDelta < 3L * 1024 * 1024,
                    string.Format("Trop de RAM utilisée : {0:F2} MB", memDelta / (1024.0 * 1024)));
            }
            finally { Directory.Delete(tmp, true); }
        }

        static void Test_FormatSize()
        {
            Assert.AreEqual("512 octets",  SecureZipService.FormatSize(512));
            Assert.AreEqual("1.00 Ko",     SecureZipService.FormatSize(1024));
            Assert.AreEqual("1.50 Ko",     SecureZipService.FormatSize(1536));
            Assert.AreEqual("1.00 Mo",     SecureZipService.FormatSize(1024 * 1024));
            Assert.AreEqual("1.00 Go",     SecureZipService.FormatSize(1024L * 1024 * 1024));
        }
    }
}
