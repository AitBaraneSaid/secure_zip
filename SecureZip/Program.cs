using System;
using System.Diagnostics;

namespace SecureZip
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                Console.WriteLine("Usage: SecureZip.exe <dossierSource> <fichierZip> <motDePasse>");
                Console.WriteLine();
                Console.WriteLine("  dossierSource   Dossier à compresser (récursif)");
                Console.WriteLine("  fichierZip      Chemin du fichier ZIP à créer (.zip)");
                Console.WriteLine("  motDePasse      Mot de passe (min. 6 caractères)");
                Console.WriteLine();
                Console.WriteLine("Exemple:");
                Console.WriteLine(@"  SecureZip.exe C:\Documents C:\Exports\archive.zip MonMotDePasse123");
                return 0;
            }

            if (args.Length != 3)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine("Erreur : Nombre d'arguments invalide.");
                Console.ResetColor();
                return 1;
            }

            var sw = Stopwatch.StartNew();
            try
            {
                int result = SecureZipService.Run(args[0], args[1], args[2]);
                sw.Stop();
                if (result == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("Durée : " + FormatElapsed(sw.Elapsed));
                    Console.ResetColor();
                }
                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine("Erreur : " + ex.Message);
                Console.ResetColor();
                return 1;
            }
        }

        private static string FormatElapsed(TimeSpan t)
        {
            if (t.TotalSeconds < 60)
                return string.Format("{0:F1} s", t.TotalSeconds);
            if (t.TotalMinutes < 60)
                return string.Format("{0} min {1:D2} s", (int)t.TotalMinutes, t.Seconds);
            return string.Format("{0} h {1:D2} min {2:D2} s", (int)t.TotalHours, t.Minutes, t.Seconds);
        }
    }
}
