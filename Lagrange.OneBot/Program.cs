using System.Reflection;
using System.Runtime;
using System.Text;
using Lagrange.OneBot.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Lagrange.OneBot;

internal abstract class Program
{
    public static async Task Main(string[] args)
    {
        string? version = Assembly
            .GetAssembly(typeof(Program))
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        // Console.BufferWidth 会引起管道无效，这里就删掉了，连带颜色设置，尽量不冒险。
        Console.WriteLine("Lagrange.OneBot");

        Console.WriteLine($"Version: {version?[^40..] ?? "unknown"}\n");
        // AutoUpdate
        var updater = new Updater.GithubUpdater();
        await updater.GetConfig();
        if (updater.Config.EnableAutoUpdate)
        {
            Console.WriteLine("Auto update enabled, Checking for updates...");
            try
            {
                if (await updater.CheckUpdate())
                {
                    Console.WriteLine($"Update available, downloading...");
                    await updater.Update();
                }
                else
                {
                    Console.WriteLine("No updates available, continuing...");
                }

                if (updater.Config.CheckInterval > 0)
                {
                    Console.WriteLine(
                        $"Interval check enabled, Next check in {updater.Config.CheckInterval} seconds."
                    );
                    updater.StartIntervalCheck();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"Error checking for updates: {e.Message}, please check your network connection or config file, use proxy if needed."
                );
            }
        }

        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        GCSettings.LatencyMode = GCLatencyMode.Batch;

        if (!File.Exists("appsettings.json"))
        {
            Console.WriteLine("No exist config file, create it now...");

            var assm = Assembly.GetExecutingAssembly();
            using var istr = assm.GetManifestResourceStream(
                "Lagrange.OneBot.Resources.appsettings.json"
            )!;
            using var temp = File.Create("appsettings.json");
            istr.CopyTo(temp);

            istr.Close();
            temp.Close();

            Console.WriteLine(
                "Please Edit the appsettings.json to set configs and press any key to continue"
            );
            // 此时选择退出程序，因为ReadKey在某些平台会崩溃
            // Console.ReadKey(true);
            return;
        }

        var builder = Host.CreateApplicationBuilder();
        ApplyDatabaseFeatureFlag(builder.Configuration);

        if (Lagrange.OneBot.Utility.FeatureFlags.DisableRealm)
        {
            Console.WriteLine("Realm features disabled.");
        }

        await builder
            .ConfigureLagrangeCore()
            .ConfigureOneBot()
            .Build()
            .InitializeMusicSigner() // Very ugly (
            .RunAsync();
    }

    private static void ApplyDatabaseFeatureFlag(IConfiguration configuration)
    {
#if ONEBOT_DISABLE_REALM
        Lagrange.OneBot.Utility.FeatureFlags.DisableRealm = true;
#else
        bool enableDatabase = configuration.GetValue("Database:Enable", false);
        bool? envDisableRealm = Environment.GetEnvironmentVariable("ONEBOT_DISABLE_REALM")?.ToLowerInvariant() switch
        {
            "1" or "true" or "yes" => true,
            "0" or "false" or "no" => false,
            _ => null
        };

        Lagrange.OneBot.Utility.FeatureFlags.DisableRealm = envDisableRealm ?? !enableDatabase;
#endif
    }
}
