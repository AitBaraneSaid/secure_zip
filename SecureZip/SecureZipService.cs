using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace SecureZip
{
    /// <summary>
    /// Orchestre la création d'un ZIP chiffré AES-256 à partir d'un dossier source.
    /// Gère les validations, l'affichage console, et délègue à <see cref="PasswordZipWriter"/>.
    /// Traitement en streaming : aucun fichier n'est chargé intégralement en RAM.
    /// </summary>
    static class SecureZipService
    {
        /// <summary>
        /// Point d'entrée principal. Valide les paramètres, scanne le dossier source
        /// récursivement, puis crée le ZIP chiffré AES-256 avec support ZIP64.
        /// </summary>
        /// <param name="sourceDir">Dossier source (tous sous-dossiers inclus).</param>
        /// <param name="zipOutput">Chemin du ZIP à créer. Dossier parent créé si absent.</param>
        /// <param name="password">Mot de passe AES-256 (minimum 6 caractères).</param>
        /// <returns>0 si succès, 1 si erreur.</returns>
        public static int Run(string sourceDir, string zipOutput, string password)
        {
            if (!Directory.Exists(sourceDir))
            {
                PrintError(string.Format("Le dossier source n'existe pas : {0}", sourceDir));
                return 1;
            }

            if (password.Length < 6)
            {
                PrintError("Le mot de passe doit faire au moins 6 caractères.");
                return 1;
            }

            string[] files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);

            if (files.Length == 0)
            {
                PrintError(string.Format("Le dossier source est vide : {0}", sourceDir));
                return 1;
            }

            string outputDir = Path.GetDirectoryName(Path.GetFullPath(zipOutput));
            if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            {
                Console.WriteLine("Création du dossier de destination : {0}", outputDir);
                Directory.CreateDirectory(outputDir);
            }

            if (File.Exists(zipOutput))
            {
                Console.Write(string.Format("Le fichier '{0}' existe déjà. Écraser ? (O/N) : ", zipOutput));
                string answer = Console.ReadLine();
                if (answer == null || answer.Trim().ToUpper() != "O")
                {
                    Console.WriteLine("Opération annulée.");
                    return 0;
                }
            }

            long totalBytes = 0;
            foreach (string f in files)
                totalBytes += new FileInfo(f).Length;

            Console.WriteLine(string.Format("Fichiers trouvés : {0} ({1})", files.Length, FormatSize(totalBytes)));
            Console.WriteLine();

            // Construction du dictionnaire chemin relatif ZIP → chemin absolu sur disque.
            // Le chemin relatif préserve l'arborescence complète dans le ZIP.
            string sourceFull = Path.GetFullPath(sourceDir).TrimEnd('\\', '/');
            var entries = new Dictionary<string, string>();

            foreach (string filePath in files)
            {
                string fullPath     = Path.GetFullPath(filePath);
                string relativePath = fullPath.Substring(sourceFull.Length).TrimStart('\\', '/');
                bool   store        = PasswordZipWriter.ShouldStore(filePath);

                Console.WriteLine(string.Format("[{0}] {1}", store ? "Store" : "Deflate", relativePath));
                entries[relativePath] = fullPath;
            }

            Console.WriteLine();

            new PasswordZipWriter().CreateFromPaths(zipOutput, entries, password, useDeflate: true);

            long zipSize = new FileInfo(zipOutput).Length;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("ZIP créé avec succès : " + zipOutput);
            Console.WriteLine("Taille du ZIP       : " + FormatSize(zipSize));
            Console.WriteLine("Taille originale    : " + FormatSize(totalBytes));
            if (totalBytes > 0)
                Console.WriteLine(string.Format("Ratio               : {0:F1}%", 100.0 * zipSize / totalBytes));
            Console.ResetColor();

            return 0;
        }

        /// <summary>
        /// Formate une taille en octets en chaîne lisible (Go, Mo, Ko, octets).
        /// </summary>
        public static string FormatSize(long bytes)
        {
            var inv = CultureInfo.InvariantCulture;
            if (bytes >= 1024L * 1024 * 1024)
                return string.Format(inv, "{0:F2} Go", bytes / (1024.0 * 1024.0 * 1024.0));
            if (bytes >= 1024L * 1024)
                return string.Format(inv, "{0:F2} Mo", bytes / (1024.0 * 1024.0));
            if (bytes >= 1024)
                return string.Format(inv, "{0:F2} Ko", bytes / 1024.0);
            return string.Format(inv, "{0} octets", bytes);
        }

        static void PrintError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine("Erreur : " + message);
            Console.ResetColor();
        }
    }
}
