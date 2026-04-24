using System;

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

            try
            {
                return SecureZipService.Run(args[0], args[1], args[2]);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine("Erreur : " + ex.Message);
                Console.ResetColor();
                return 1;
            }
        }
    }
}
