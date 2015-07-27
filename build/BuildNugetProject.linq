<Query Kind="Program" />

void Main()
{
    var buildDir = Path.GetDirectoryName(Util.CurrentQueryPath);
    var rootDir = new Uri(Path.Combine(buildDir, "..")).LocalPath;
    var srcDir = Path.Combine(rootDir, "src");
    
    var artifactsDir = CreateSpecificArtifactDirectory(rootDir);
    var contentDir = CreateContentDirectory(artifactsDir);
    
    var embeddedNativeLibraryFileTemplate = GetEmbeddedNativeLibraryFileTemplate(srcDir);
    
    var version = GetVersion(srcDir);

    WriteContentFiles(contentDir, embeddedNativeLibraryFileTemplate);
    WriteNuspecFile(buildDir, artifactsDir, embeddedNativeLibraryFileTemplate, version);
    
    artifactsDir.Dump(); // This allows build.cmd to use the artifactsDir for nuget pack.
}

private static string CreateSpecificArtifactDirectory(string rootDir)
{
    const string nowFormat = "yyyy-MM-dd_HH-mm-ss-ffff";
    
    var rootArtifactsDir = Path.Combine(rootDir, "artifacts");
    
    if (!Directory.Exists(rootArtifactsDir))
    {
        Directory.CreateDirectory(rootArtifactsDir);
    }
    
    var now = DateTime.Now;
    
    while (Directory.GetDirectories(rootArtifactsDir).Any(d => d == now.ToString(nowFormat)))
    {
        now += TimeSpan.FromMilliseconds(1);
    }
    
    var artifactsDir = Path.Combine(rootArtifactsDir, now.ToString(nowFormat));
    
    Directory.CreateDirectory(artifactsDir);
    
    return artifactsDir;
}

private static string CreateContentDirectory(string artifactsDir)
{
    var contentDir = Path.Combine(artifactsDir, "content");
    Directory.CreateDirectory(contentDir);
    return contentDir;
}

private static FileTemplate GetEmbeddedNativeLibraryFileTemplate(string srcDir)
{
    return new FileTemplate
    {
        Name = "EmbeddedNativeLibrary.cs.pp",
        Contents = File.ReadAllText(Path.Combine(srcDir, "EmbeddedNativeLibrary.cs"))
    };
}

private static string GetVersion(string srcDir)
{
    var assemblyInfoContents = File.ReadAllText(Path.Combine(srcDir, "Properties", "AssemblyInfo.cs"));
    var match = Regex.Match(assemblyInfoContents, @"\[assembly: AssemblyInformationalVersion\(""([^""]+)""\)]");
    return match.Groups[1].Value;
}

private static void WriteContentFiles(string contentDir, FileTemplate embeddedNativeLibraryFileTemplate)
{
    var embeddedNativeLibrary = Path.Combine(contentDir, "Rock.EmbeddedNativeLibrary");
    
    Directory.CreateDirectory(embeddedNativeLibrary);
    
    var contents = embeddedNativeLibraryFileTemplate.Contents.Replace("namespace Rock.Reflection", "namespace $rootnamespace$");

    File.WriteAllText(Path.Combine(embeddedNativeLibrary, embeddedNativeLibraryFileTemplate.Name), contents);
}

private static void WriteNuspecFile(string buildDir, string artifactsDir, FileTemplate embeddedNativeLibraryFileTemplate, string version)
{
    const string nuspecFile = "Rock.EmbeddedNativeLibrary.nuspec";
    const string xsd = "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd";
    
    var nuspecContents = File.ReadAllText(Path.Combine(buildDir, nuspecFile));
    
    var xml = XDocument.Parse(nuspecContents);
    
    xml.Root.Element(XName.Get("metadata", xsd)).Element(XName.Get("version", xsd)).Value = version;
    
    var filesElement = xml.Root.Element(XName.Get("files", xsd));
    
    filesElement.AddFirst(embeddedNativeLibraryFileTemplate.GetXElement(xsd));
    
    File.WriteAllText(Path.Combine(artifactsDir, nuspecFile), xml.ToString());
}

private class FileTemplate
{
    public string Name { get; set; }
    public string Contents { get; set; }
    
    public XElement GetXElement(string xsd)
    {
        var value = string.Format(@"content\Rock.EmbeddedNativeLibrary\{0}", Name);

        return
            new XElement(XName.Get("file", xsd),
                new XAttribute("src", value),
                new XAttribute("target", value));
    }
}